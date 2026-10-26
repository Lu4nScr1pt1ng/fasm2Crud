; PostgreSQL client: frontend/backend protocol v3 over io_uring.
;
; Each worker owns API_DB_CONNS connections. A connection goes through
;   IDLE -> CONNECTING -> AUTH (SCRAM-SHA-256) -> PREPARING -> READY
; and on any failure to BROKEN, then IDLE again after an exponential
; backoff (100 ms doubling to 5 s, with jitter).
;
; Queries are pipelined: each one is Bind + Execute + Sync, so an error
; aborts only that query, and responses come back in order. A FIFO per
; connection matches every ReadyForQuery to the HTTP request waiting for
; it. Parameters and results use the text format: rows go straight into
; JSON, and parameters never touch the SQL text.
;
; Every statement is prepared once per connection (pg_statement below).

PG_MAX_CONNS		= 8
PG_MAX_INFLIGHT		= 128		; power of two
PG_TX_CAP		= 262144		; room for a burst of large queries
PG_RX_CAP		= 65536
PG_TX_WARM		= 65536		; kept resident; the rest goes back when idle
PG_RX_WARM		= 16384
PG_HANDSHAKE_TIMEOUT	= 5		; ticks
PG_QUERY_TIMEOUT	= 15		; ticks without any reply while queries wait
PG_BACKOFF_MIN		= 100		; ms
PG_BACKOFF_MAX		= 5000

PGS_IDLE	= 0
PGS_CONNECTING	= 1
PGS_AUTH	= 2
PGS_PREPARING	= 3
PGS_READY	= 4
PGS_BROKEN	= 5

PGF_RECV	= 1 shl 0
PGF_SEND	= 1 shl 1
PGF_AUTH_OK	= 1 shl 2
PGF_QUERY_ERROR	= 1 shl 3

; Result status handed to continuations.
PGR_OK		= 0
PGR_SQL_ERROR	= 1		; sqlstate in g_pg_sqlstate
PGR_UNAVAILABLE	= 2

PG_STATE	= 0
PG_FD		= 4
PG_FLAGS	= 8
PG_PENDING	= 12		; io_uring operations in flight on this connection
PG_TX_LEN	= 16
PG_TX_SENT	= 20
PG_RX_LEN	= 24
PG_RESP		= 28		; start of the current query's response in rx
PG_SCAN		= 32		; next unparsed message in rx
PG_QHEAD	= 36
PG_QTAIL	= 40
PG_BACKOFF	= 44
PG_SINCE	= 48		; tick of the last progress
PG_SQLSTATE	= 52		; 5 characters
PG_ADDR		= 64		; sockaddr_in
PG_TS		= 80		; backoff timespec
PG_FIRST_LEN	= 96
PG_TX_PEAK	= 100		; tick tx last went past PG_TX_WARM
PG_RX_PEAK	= 104
PG_GREW		= 108		; 1: tx went past its warm size, 2: rx did
PG_SCRAM	= 128		; SC_SIZE
PG_NONCE	= 208		; 24 base64 characters
PG_FIRST	= 240		; client-first-message-bare
PG_SERVER	= 512		; server-first-message
PG_QUEUE	= 1024		; PG_MAX_INFLIGHT entries of 16 bytes
PG_TX		= 4096
PG_RX		= PG_TX + PG_TX_CAP
PG_SIZE		= PG_RX + PG_RX_CAP

; Queue entry: the HTTP request a reply belongs to.
PQ_SLOT		= 0
PQ_GEN		= 4
PQ_CONT		= 8
PQ_CTX		= 12		; auth context id + 1, or 0
PQ_SIZE		= 16

PG_NONCE_BYTES	= 18		; 24 base64 characters, no padding

bss
	align 4096
	g_pg:		rb PG_MAX_CONNS * PG_SIZE
	g_pg_count	dd ?
	g_pg_next	dd ?		; round robin
	g_db_enabled	dd ?
	g_db_addr	dd ?		; IPv4, network byte order
	g_db_port	dd ?
	g_db_user_len	dd ?
	g_db_name_len	dd ?
	g_db_pass_len	dd ?
	g_pg_sqlstate	dq ?
	g_db_user	dq ?
	g_db_name	dq ?
	g_db_pass	dq ?
end bss

rodata
	align 8
	pg_connect_timeout dq 3, 0
	pg_sasl_mechanism db 'SCRAM-SHA-256',0
	PG_SASL_MECHANISM_LEN = $ - pg_sasl_mechanism
	pg_startup_fixed db 'application_name',0,'fasm2crud',0
			 db 'client_encoding',0,'UTF8',0
			 db 'TimeZone',0,'UTC',0
			 db 'statement_timeout',0,'5000',0
			 db 0
	PG_STARTUP_FIXED_LEN = $ - pg_startup_fixed
end rodata

cstring pg_key_user, 'user',0
cstring pg_key_database, 'database',0

; Prepared statements: pg_statement ID, 'SQL' defines ID and appends to
; pg_stmt_tbl (dq name, name length with NUL, sql, sql length with NUL).
virtual at 0
	PGSTMT.buffer::
end virtual
PGSTMT.count = 0

macro pg_statement id*, sql&
	local n, q
	cstring n, 's', '0' + PGSTMT.count / 10, '0' + PGSTMT.count mod 10, 0
	cstring q, sql, 0
	id := PGSTMT.count
	PGSTMT.count = PGSTMT.count + 1
	virtual PGSTMT.buffer
		dq n, n.len, q, q.len
	end virtual
end macro

pg_statement STMT_PING, 'SELECT 1'
pg_statement STMT_INSERT_USER, 'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id'
pg_statement STMT_USER_BY_EMAIL, 'SELECT id, password_hash, session_epoch FROM users WHERE email = $1'
pg_statement STMT_INSERT_REFRESH, \
	'INSERT INTO refresh_tokens (token_hash, user_id, family_id, expires_at) ', \
	'VALUES ($1::bytea, $2::uuid, uuidv7(), now() + interval ''30 days'')'
; Rotation in one statement. The row lock serializes two refreshes of the
; same token; the loser sees it rotated, which counts as reuse and revokes
; the whole family (every token of that login). A family with any revoked
; token never rotates again: that also covers the winner's new token, which
; the loser's snapshot cannot see, and a logout racing a refresh.
pg_statement STMT_ROTATE_REFRESH, \
	'WITH t AS (SELECT token_hash, user_id, family_id, rotated_at, revoked_at, expires_at ', \
	'FROM refresh_tokens WHERE token_hash = $1::bytea FOR UPDATE), ', \
	'rot AS (UPDATE refresh_tokens r SET rotated_at = now() FROM t ', \
	'WHERE r.token_hash = t.token_hash AND t.rotated_at IS NULL AND t.revoked_at IS NULL ', \
	'AND t.expires_at > now() AND NOT EXISTS (SELECT 1 FROM refresh_tokens x ', \
	'WHERE x.family_id = t.family_id AND x.revoked_at IS NOT NULL) ', \
	'RETURNING r.user_id, r.family_id), ', \
	'reuse AS (UPDATE refresh_tokens r SET revoked_at = now() FROM t ', \
	'WHERE r.family_id = t.family_id AND t.rotated_at IS NOT NULL AND r.revoked_at IS NULL RETURNING 1), ', \
	'ins AS (INSERT INTO refresh_tokens (token_hash, user_id, family_id, expires_at) ', \
	'SELECT $2::bytea, user_id, family_id, now() + interval ''30 days'' FROM rot RETURNING user_id) ', \
	'SELECT u.id, u.session_epoch FROM ins JOIN users u ON u.id = ins.user_id'
; Housekeeping (src/app/maintenance.inc). A token is kept until it expires
; even when rotated or revoked: reuse detection and a revoked family's
; refusal to rotate both need its row.
pg_statement STMT_PURGE_REFRESH, \
	'DELETE FROM refresh_tokens WHERE token_hash IN (SELECT token_hash FROM refresh_tokens ', \
	'WHERE expires_at < now() ORDER BY expires_at LIMIT 5000)'
pg_statement STMT_REVOKE_FAMILY, \
	'UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = ', \
	'(SELECT family_id FROM refresh_tokens WHERE token_hash = $1::bytea) AND revoked_at IS NULL'

; Notes (src/app/notes.inc). Times are RFC 3339 text, made by the database.
; Every notes statement checks the session first: "a" holds the user only
; while the token's session epoch is still the current one, so a token from
; before logout-all, a password change or a deleted account finds nothing.
; Each statement returns no row at all for a dead session (401), and at
; least one row otherwise.
;
; INSERT ($1 user, $2 title, $3 body, $4 epoch): the note.
pg_statement STMT_NOTE_INSERT, \
	'WITH a AS (SELECT id FROM users WHERE id = $1::uuid AND session_epoch = $4::int) ', \
	'INSERT INTO notes (user_id, title, body) SELECT a.id, $2, COALESCE($3, '''') FROM a ', \
	'RETURNING id, title, body, version, ', \
	'to_char(created_at AT TIME ZONE ''UTC'', ''YYYY-MM-DD"T"HH24:MI:SS.US"Z"''), ', \
	'to_char(updated_at AT TIME ZONE ''UTC'', ''YYYY-MM-DD"T"HH24:MI:SS.US"Z"'')'
; GET ($1 id, $2 user, $3 epoch): the note, or a row of NULLs (404).
pg_statement STMT_NOTE_GET, \
	'WITH a AS (SELECT id FROM users WHERE id = $2::uuid AND session_epoch = $3::int) ', \
	'SELECT n.id, n.title, n.body, n.version, ', \
	'to_char(n.created_at AT TIME ZONE ''UTC'', ''YYYY-MM-DD"T"HH24:MI:SS.US"Z"''), ', \
	'to_char(n.updated_at AT TIME ZONE ''UTC'', ''YYYY-MM-DD"T"HH24:MI:SS.US"Z"'') ', \
	'FROM a LEFT JOIN notes n ON n.id = $1::uuid AND n.user_id = a.id'
; UPDATE ($1 id, $2 user, $3 version, $4 title, $5 body, $6 epoch): the
; updated note (NULLs when the version did not match: 412) and the current
; version (NULL when there is no such note: 404). The row lock makes a
; concurrent writer re-check the version after the first one commits.
pg_statement STMT_NOTE_UPDATE, \
	'WITH a AS (SELECT id FROM users WHERE id = $2::uuid AND session_epoch = $6::int), ', \
	'cur AS (SELECT n.version FROM notes n JOIN a ON n.user_id = a.id WHERE n.id = $1::uuid), ', \
	'upd AS (UPDATE notes n SET title = COALESCE($4, n.title), body = COALESCE($5, n.body), ', \
	'version = n.version + 1, updated_at = now() FROM cur ', \
	'WHERE n.id = $1::uuid AND n.user_id = $2::uuid AND n.version = $3::int ', \
	'RETURNING n.id, n.title, n.body, n.version, n.created_at, n.updated_at) ', \
	'SELECT upd.id, upd.title, upd.body, upd.version, ', \
	'to_char(upd.created_at AT TIME ZONE ''UTC'', ''YYYY-MM-DD"T"HH24:MI:SS.US"Z"''), ', \
	'to_char(upd.updated_at AT TIME ZONE ''UTC'', ''YYYY-MM-DD"T"HH24:MI:SS.US"Z"''), ', \
	'cur.version FROM a LEFT JOIN cur ON true LEFT JOIN upd ON true'
; DELETE ($1 id, $2 user, $3 version, $4 epoch): the current version (NULL:
; 404) and how many rows went.
pg_statement STMT_NOTE_DELETE, \
	'WITH a AS (SELECT id FROM users WHERE id = $2::uuid AND session_epoch = $4::int), ', \
	'cur AS (SELECT n.version FROM notes n JOIN a ON n.user_id = a.id WHERE n.id = $1::uuid), ', \
	'del AS (DELETE FROM notes n USING cur WHERE n.id = $1::uuid AND n.user_id = $2::uuid ', \
	'AND n.version = $3::int RETURNING n.id) ', \
	'SELECT cur.version, (SELECT count(*) FROM del) FROM a LEFT JOIN cur ON true'
; Keyset pages over notes_user_id_id ($1 user, $2 limit + 1, [$3 cursor],
; last: epoch). An empty page is one row of NULLs.
pg_statement STMT_NOTES_PAGE, \
	'WITH a AS (SELECT id FROM users WHERE id = $1::uuid AND session_epoch = $3::int) ', \
	'SELECT n.id, n.title, n.version, to_char(n.updated_at AT TIME ZONE ''UTC'', ''YYYY-MM-DD"T"HH24:MI:SS.US"Z"'') ', \
	'FROM a LEFT JOIN LATERAL (SELECT id, title, version, updated_at FROM notes ', \
	'WHERE user_id = a.id ORDER BY id DESC LIMIT $2::int) n ON true ORDER BY n.id DESC'
pg_statement STMT_NOTES_PAGE_AFTER, \
	'WITH a AS (SELECT id FROM users WHERE id = $1::uuid AND session_epoch = $4::int) ', \
	'SELECT n.id, n.title, n.version, to_char(n.updated_at AT TIME ZONE ''UTC'', ''YYYY-MM-DD"T"HH24:MI:SS.US"Z"'') ', \
	'FROM a LEFT JOIN LATERAL (SELECT id, title, version, updated_at FROM notes ', \
	'WHERE user_id = a.id AND id < $3::uuid ORDER BY id DESC LIMIT $2::int) n ON true ORDER BY n.id DESC'

; Sessions (src/app/auth.inc). Each returns how many users matched: 0 when
; the session is already dead.
; Every session of the user ends ($1 user, $2 epoch).
pg_statement STMT_LOGOUT_ALL, \
	'WITH u AS (UPDATE users SET session_epoch = session_epoch + 1 ', \
	'WHERE id = $1::uuid AND session_epoch = $2::int RETURNING id), ', \
	'r AS (UPDATE refresh_tokens t SET revoked_at = now() FROM u ', \
	'WHERE t.user_id = u.id AND t.revoked_at IS NULL RETURNING 1) ', \
	'SELECT count(*) FROM u'
; The stored hash, for a live session ($1 user, $2 epoch); no row otherwise.
pg_statement STMT_SESSION_HASH, \
	'SELECT password_hash FROM users WHERE id = $1::uuid AND session_epoch = $2::int'
; New password; every session ends ($1 user, $2 epoch, $3 PHC string).
pg_statement STMT_SET_PASSWORD, \
	'WITH u AS (UPDATE users SET password_hash = $3, session_epoch = session_epoch + 1 ', \
	'WHERE id = $1::uuid AND session_epoch = $2::int RETURNING id), ', \
	'r AS (UPDATE refresh_tokens t SET revoked_at = now() FROM u ', \
	'WHERE t.user_id = u.id AND t.revoked_at IS NULL RETURNING 1) ', \
	'SELECT count(*) FROM u'
; The account and, by cascade, its notes and tokens ($1 user, $2 epoch).
pg_statement STMT_DELETE_USER, \
	'WITH u AS (DELETE FROM users WHERE id = $1::uuid AND session_epoch = $2::int RETURNING id) ', \
	'SELECT count(*) FROM u'

rodata
	align 8
	pg_stmt_tbl:
	virtual PGSTMT.buffer
		load PGSTMT.data:$-$$ from $$
	end virtual
	db PGSTMT.data
end rodata

macro pg_ptr reg*, index*
	imul	reg#d,index,PG_SIZE
	lea	reg,[g_pg+reg]
end macro

; Message framing into the transmit buffer: rdi = write cursor.
; pg_begin saves the length position in r8; pg_end patches it.
macro pg_begin type*
	mov	byte [rdi],type
	lea	r8,[rdi+1]
	add	rdi,5
end macro

macro pg_end
	mov	rax,rdi
	sub	rax,r8
	bswap	eax
	mov	[r8],eax
end macro

macro pg_be16 value*
	mov	word [rdi],((value) shr 8) or (((value) and 0xFF) shl 8)
	add	rdi,2
end macro

macro pg_bytes ptr*, len*
	mov	rsi,ptr
	mov	ecx,len
	rep	movsb
end macro

; ---------------------------------------------------------------- setup

; Called once per worker after the ring exists.
pg_init:
	cmp	dword [g_db_enabled],0
	je	.done
	push	rbx
	push	r13
	xor	ebx,ebx
.each:
	cmp	ebx,[g_pg_count]
	jae	.started
	pg_ptr	r13,ebx
	mov	dword [r13+PG_BACKOFF],PG_BACKOFF_MIN
	mov	eax,[g_db_port]
	xchg	al,ah
	shl	eax,16
	or	eax,AF_INET
	mov	[r13+PG_ADDR],eax
	mov	eax,[g_db_addr]
	mov	[r13+PG_ADDR+4],eax
	call	pg_connect
	inc	ebx
	jmp	.each
.started:
	pop	r13
	pop	rbx
.done:
	ret

cstring pg_msg_socket, 'cannot create a socket'
cstring pg_msg_connect, 'cannot connect'

; ebx = index, r13 = connection.
pg_connect:
	mov	edi,AF_INET
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.no_socket
	mov	[r13+PG_FD],eax
	; Low latency, and dead peers detected in seconds rather than hours.
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_NODELAY
	mov	ecx,1
	call	.option
	mov	esi,SOL_SOCKET
	mov	edx,SO_KEEPALIVE
	mov	ecx,1
	call	.option
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_KEEPIDLE
	mov	ecx,10
	call	.option
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_KEEPINTVL
	mov	ecx,5
	call	.option
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_KEEPCNT
	mov	ecx,3
	call	.option
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_USER_TIMEOUT
	mov	ecx,10000
	call	.option

	mov	dword [r13+PG_STATE],PGS_CONNECTING
	xor	eax,eax
	mov	[r13+PG_FLAGS],eax
	mov	[r13+PG_TX_LEN],eax
	mov	[r13+PG_TX_SENT],eax
	mov	[r13+PG_RX_LEN],eax
	mov	[r13+PG_RESP],eax
	mov	[r13+PG_SCAN],eax
	mov	eax,[g_tick]
	mov	[r13+PG_SINCE],eax

	; connect, linked to a timeout so an unreachable host fails fast.
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CONNECT
	mov	byte [rax+SQE_FLAGS],IOSQE_IO_LINK
	mov	ecx,[r13+PG_FD]
	mov	[rax+SQE_FD],ecx
	lea	rcx,[r13+PG_ADDR]
	mov	[rax+SQE_ADDR],rcx
	mov	qword [rax+SQE_OFF],16
	mov	rcx,OP_PG_CONNECT shl 32
	or	rcx,rbx
	mov	[rax+SQE_USER_DATA],rcx
	inc	dword [r13+PG_PENDING]
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_LINK_TIMEOUT
	lea	rcx,[pg_connect_timeout]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],1
	mov	rcx,OP_IGNORE shl 32
	mov	[rax+SQE_USER_DATA],rcx
	ret

.option:
	sub	rsp,8
	mov	[rsp],ecx
	mov	edi,[r13+PG_FD]
	mov	r10,rsp
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	add	rsp,8
	ret

.no_socket:
	mov	r14,rax
	mov	dword [r13+PG_STATE],PGS_BROKEN
	lea	rsi,[pg_msg_socket]
	mov	edx,pg_msg_socket.len
	call	pg_log_failure
	jmp	pg_schedule_retry

on_pg_connect:
	pg_ptr	r13,ebx
	dec	dword [r13+PG_PENDING]
	cmp	dword [r13+PG_STATE],PGS_CONNECTING
	jne	pg_release_if_idle
	test	r14d,r14d
	js	.failed
	mov	dword [r13+PG_STATE],PGS_AUTH
	mov	eax,[g_tick]
	mov	[r13+PG_SINCE],eax
	call	pg_send_startup
	jmp	pg_arm_recv
.failed:
	lea	rsi,[pg_msg_connect]
	mov	edx,pg_msg_connect.len
	jmp	pg_fail

; StartupMessage: length, protocol 3.0, then name/value pairs.
pg_send_startup:
	mov	eax,[r13+PG_TX_LEN]
	lea	rdi,[r13+PG_TX+rax]
	mov	r8,rdi
	add	rdi,4
	mov	dword [rdi],0x00000300		; 196608, big endian
	add	rdi,4
	pg_bytes pg_key_user, pg_key_user.len
	mov	rsi,[g_db_user]
	mov	ecx,[g_db_user_len]
	rep	movsb
	mov	byte [rdi],0
	inc	rdi
	pg_bytes pg_key_database, pg_key_database.len
	mov	rsi,[g_db_name]
	mov	ecx,[g_db_name_len]
	rep	movsb
	mov	byte [rdi],0
	inc	rdi
	lea	rsi,[pg_startup_fixed]
	mov	ecx,PG_STARTUP_FIXED_LEN
	rep	movsb
	mov	rax,rdi
	sub	rax,r8
	bswap	eax
	mov	[r8],eax
	jmp	pg_commit_tx

; rdi = end of the data just written to tx: record it and send.
pg_commit_tx:
	lea	rax,[r13+PG_TX]
	sub	rdi,rax
	mov	[r13+PG_TX_LEN],edi
	cmp	edi,PG_TX_WARM
	jbe	pg_flush
	mov	eax,[g_tick]
	mov	[r13+PG_TX_PEAK],eax
	or	dword [r13+PG_GREW],1

pg_flush:
	mov	eax,[r13+PG_TX_LEN]
	cmp	eax,[r13+PG_TX_SENT]
	jbe	.done
	test	dword [r13+PG_FLAGS],PGF_SEND
	jnz	.done
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_SEND
	mov	ecx,[r13+PG_FD]
	mov	[rax+SQE_FD],ecx
	mov	ecx,[r13+PG_TX_SENT]
	lea	rdx,[r13+PG_TX+rcx]
	mov	[rax+SQE_ADDR],rdx
	mov	edx,[r13+PG_TX_LEN]
	sub	edx,ecx
	mov	[rax+SQE_LEN],edx
	mov	dword [rax+SQE_OP_FLAGS],MSG_NOSIGNAL
	mov	rcx,OP_PG_SEND shl 32
	or	rcx,rbx
	mov	[rax+SQE_USER_DATA],rcx
	inc	dword [r13+PG_PENDING]
	or	dword [r13+PG_FLAGS],PGF_SEND
.done:
	ret

pg_arm_recv:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_RECV
	mov	ecx,[r13+PG_FD]
	mov	[rax+SQE_FD],ecx
	mov	ecx,[r13+PG_RX_LEN]
	lea	rdx,[r13+PG_RX+rcx]
	mov	[rax+SQE_ADDR],rdx
	mov	edx,PG_RX_CAP
	sub	edx,ecx
	mov	[rax+SQE_LEN],edx
	mov	rcx,OP_PG_RECV shl 32
	or	rcx,rbx
	mov	[rax+SQE_USER_DATA],rcx
	inc	dword [r13+PG_PENDING]
	or	dword [r13+PG_FLAGS],PGF_RECV
	ret

cstring pg_msg_send, 'send failed'

on_pg_send:
	pg_ptr	r13,ebx
	dec	dword [r13+PG_PENDING]
	and	dword [r13+PG_FLAGS],not PGF_SEND
	cmp	dword [r13+PG_STATE],PGS_BROKEN
	je	pg_release_if_idle
	test	r14d,r14d
	jle	.failed
	add	[r13+PG_TX_SENT],r14d
	; Move what is left (and whatever was queued meanwhile) to the front.
	mov	ecx,[r13+PG_TX_LEN]
	mov	esi,[r13+PG_TX_SENT]
	sub	ecx,esi
	mov	[r13+PG_TX_LEN],ecx
	mov	dword [r13+PG_TX_SENT],0
	jz	.done
	lea	rdi,[r13+PG_TX]
	lea	rsi,[rdi+rsi]
	rep	movsb
	jmp	pg_flush
.done:
	ret
.failed:
	lea	rsi,[pg_msg_send]
	mov	edx,pg_msg_send.len
	jmp	pg_fail

cstring pg_msg_closed, 'connection closed by the database'
cstring pg_msg_too_large, 'reply larger than the receive buffer'

on_pg_recv:
	pg_ptr	r13,ebx
	dec	dword [r13+PG_PENDING]
	and	dword [r13+PG_FLAGS],not PGF_RECV
	cmp	dword [r13+PG_STATE],PGS_BROKEN
	je	pg_release_if_idle
	test	r14d,r14d
	jle	.closed
	add	[r13+PG_RX_LEN],r14d
	mov	eax,[g_tick]
	mov	[r13+PG_SINCE],eax
	cmp	dword [r13+PG_RX_LEN],PG_RX_WARM
	jbe	@f
	mov	[r13+PG_RX_PEAK],eax
	or	dword [r13+PG_GREW],2
@@:
	call	pg_process
	cmp	dword [r13+PG_STATE],PGS_BROKEN
	je	.done
	cmp	dword [r13+PG_RX_LEN],PG_RX_CAP
	jae	.too_large
	jmp	pg_arm_recv
.done:
	ret
.closed:
	lea	rsi,[pg_msg_closed]
	mov	edx,pg_msg_closed.len
	jmp	pg_fail
.too_large:
	lea	rsi,[pg_msg_too_large]
	mov	edx,pg_msg_too_large.len
	jmp	pg_fail

; ---------------------------------------------------------------- replies

cstring pg_msg_protocol, 'protocol violation'

; Parse every complete message in rx, then compact.
pg_process:
	push	r14
	push	r15
.message:
	mov	r14d,[r13+PG_SCAN]
	mov	ecx,[r13+PG_RX_LEN]
	sub	ecx,r14d
	cmp	ecx,5
	jb	.compact
	lea	rsi,[r13+PG_RX+r14]
	mov	eax,[rsi+1]
	bswap	eax
	cmp	eax,4
	jb	.violation
	cmp	eax,PG_RX_CAP - 1
	jae	.violation
	lea	r15d,[rax+1]			; whole message
	cmp	r15d,ecx
	ja	.compact
	movzx	eax,byte [rsi]
	lea	edx,[r15-5]			; body length
	add	rsi,5				; body
	mov	ecx,[r13+PG_STATE]
	cmp	ecx,PGS_READY
	je	.ready
	cmp	ecx,PGS_AUTH
	je	.auth
	cmp	ecx,PGS_PREPARING
	jne	.done
	call	pg_prepare_message
	jmp	.handled
.auth:
	call	pg_auth_message
	jmp	.handled
.ready:
	call	pg_ready_message
.handled:
	cmp	dword [r13+PG_STATE],PGS_BROKEN
	je	.done
	add	r14d,r15d
	mov	[r13+PG_SCAN],r14d
	cmp	dword [r13+PG_STATE],PGS_READY
	je	.message
	mov	[r13+PG_RESP],r14d		; outside queries nothing is kept
	jmp	.message
.compact:
	; Keep the current query's response from its first message on.
	mov	esi,[r13+PG_RESP]
	test	esi,esi
	jz	.done
	mov	ecx,[r13+PG_RX_LEN]
	sub	ecx,esi
	mov	[r13+PG_RX_LEN],ecx
	sub	[r13+PG_SCAN],esi
	mov	dword [r13+PG_RESP],0
	lea	rdi,[r13+PG_RX]
	lea	rsi,[rdi+rsi]
	rep	movsb
.done:
	pop	r15
	pop	r14
	ret
.violation:
	lea	rsi,[pg_msg_protocol]
	mov	edx,pg_msg_protocol.len
	call	pg_fail
	jmp	.done

cstring pg_msg_no_scram, 'the server does not offer SCRAM-SHA-256'
cstring pg_msg_bad_challenge, 'invalid SCRAM challenge'
cstring pg_msg_bad_server, 'the server failed SCRAM verification'
cstring pg_msg_auth_method, 'the server asked for an authentication method other than SCRAM-SHA-256'
cstring pg_msg_auth_failed, 'authentication failed'
cstring pg_msg_auth_incomplete, 'ready before authentication completed'

; eax = type, rsi = body, edx = body length.
pg_auth_message:
	cmp	al,'R'
	je	.authentication
	cmp	al,'E'
	je	.error
	cmp	al,'Z'
	je	.ready
	ret					; ParameterStatus, BackendKeyData, notices
.error:
	call	pg_log_error
	lea	rsi,[pg_msg_auth_failed]
	mov	edx,pg_msg_auth_failed.len
	jmp	pg_fail
.ready:
	test	dword [r13+PG_FLAGS],PGF_AUTH_OK
	jz	.incomplete
	mov	dword [r13+PG_STATE],PGS_PREPARING
	jmp	pg_send_prepare
.incomplete:
	lea	rsi,[pg_msg_auth_incomplete]
	mov	edx,pg_msg_auth_incomplete.len
	jmp	pg_fail

.authentication:
	cmp	edx,4
	jb	.method
	mov	eax,[rsi]
	bswap	eax
	add	rsi,4
	sub	edx,4
	test	eax,eax
	jz	.ok
	cmp	eax,10
	je	.sasl
	cmp	eax,11
	je	.challenge
	cmp	eax,12
	je	.final
.method:
	; Never fall back to cleartext or MD5.
	lea	rsi,[pg_msg_auth_method]
	mov	edx,pg_msg_auth_method.len
	jmp	pg_fail
.ok:
	or	dword [r13+PG_FLAGS],PGF_AUTH_OK
	ret

.sasl:
	; Mechanism list: NUL-terminated names, then an empty one.
	lea	rdi,[rsi+rdx]
.mechanism:
	cmp	rsi,rdi
	jae	.no_scram
	cmp	byte [rsi],0
	je	.no_scram
	lea	rax,[rsi+PG_SASL_MECHANISM_LEN]
	cmp	rax,rdi
	ja	.no_scram
	push	rsi
	push	rdi
	lea	rdi,[pg_sasl_mechanism]
	mov	ecx,PG_SASL_MECHANISM_LEN
	repe	cmpsb
	pop	rdi
	pop	rsi
	je	pg_send_client_first
.skip_name:
	cmp	rsi,rdi
	jae	.no_scram
	lodsb
	test	al,al
	jnz	.skip_name
	jmp	.mechanism
.no_scram:
	lea	rsi,[pg_msg_no_scram]
	mov	edx,pg_msg_no_scram.len
	jmp	pg_fail

.challenge:
	cmp	edx,SCRAM_MAX_MSG
	ja	.bad_challenge
	lea	rdi,[r13+PG_SERVER]
	mov	ecx,edx
	rep	movsb
	lea	rax,[r13+PG_SERVER]
	mov	[r13+PG_SCRAM+SC_SERVER],rax
	mov	[r13+PG_SCRAM+SC_SERVER_LEN],edx
	; SASLResponse with client-final-message, built straight into tx.
	mov	eax,[r13+PG_TX_LEN]
	lea	rdi,[r13+PG_TX+rax]
	push	rdi
	lea	rdi,[r13+PG_SCRAM]
	mov	rsi,[rsp]
	add	rsi,5
	call	scram_client_final
	pop	rdi
	test	rax,rax
	js	.bad_challenge
	mov	byte [rdi],'p'
	lea	ecx,[rax+4]
	bswap	ecx
	mov	[rdi+1],ecx
	lea	rdi,[rdi+rax+5]
	jmp	pg_commit_tx
.bad_challenge:
	lea	rsi,[pg_msg_bad_challenge]
	mov	edx,pg_msg_bad_challenge.len
	jmp	pg_fail

.final:
	lea	rdi,[r13+PG_SCRAM]
	call	scram_verify_final
	test	eax,eax
	jnz	.verified
	lea	rsi,[pg_msg_bad_server]
	mov	edx,pg_msg_bad_server.len
	jmp	pg_fail
.verified:
	ret

; SASLInitialResponse: mechanism, then "n,," client-first-message-bare,
; where bare = "n=,r=" nonce (PostgreSQL takes the user from the startup).
pg_send_client_first:
	lea	rdi,[r13+PG_FIRST+64]		; scratch for the random bytes
	mov	esi,PG_NONCE_BYTES
	call	random_bytes
	lea	rdi,[r13+PG_NONCE]
	lea	rsi,[r13+PG_FIRST+64]
	mov	edx,PG_NONCE_BYTES
	call	base64_encode
	lea	rdi,[r13+PG_FIRST]
	mov	dword [rdi],'n=,r'
	mov	byte [rdi+4],'='
	add	rdi,5
	lea	rsi,[r13+PG_NONCE]
	mov	ecx,24
	rep	movsb
	mov	dword [r13+PG_FIRST_LEN],29

	lea	rax,[r13+PG_SCRAM]
	mov	rcx,[g_db_pass]
	mov	[rax+SC_PASSWORD],rcx
	mov	ecx,[g_db_pass_len]
	mov	[rax+SC_PASSWORD_LEN],ecx
	lea	rcx,[r13+PG_NONCE]
	mov	[rax+SC_NONCE],rcx
	mov	dword [rax+SC_NONCE_LEN],24
	lea	rcx,[r13+PG_FIRST]
	mov	[rax+SC_FIRST],rcx
	mov	dword [rax+SC_FIRST_LEN],29

	mov	eax,[r13+PG_TX_LEN]
	lea	rdi,[r13+PG_TX+rax]
	pg_begin 'p'
	pg_bytes pg_sasl_mechanism, PG_SASL_MECHANISM_LEN
	mov	eax,3 + 29
	bswap	eax
	mov	[rdi],eax
	add	rdi,4
	mov	word [rdi],'n,'
	mov	byte [rdi+2],','
	add	rdi,3
	lea	rsi,[r13+PG_FIRST]
	mov	ecx,29
	rep	movsb
	pg_end
	jmp	pg_commit_tx

; Parse every statement, then Sync.
pg_send_prepare:
	push	rbx
	mov	eax,[r13+PG_TX_LEN]
	lea	rdi,[r13+PG_TX+rax]
	xor	ebx,ebx
.statement:
	cmp	ebx,PGSTMT.count
	jae	.sync
	mov	eax,ebx
	shl	eax,5
	pg_begin 'P'
	pg_bytes [pg_stmt_tbl+rax], [pg_stmt_tbl+rax+8]
	mov	eax,ebx
	shl	eax,5
	pg_bytes [pg_stmt_tbl+rax+16], [pg_stmt_tbl+rax+24]
	pg_be16	0				; no parameter types: inferred
	pg_end
	inc	ebx
	jmp	.statement
.sync:
	pg_begin 'S'
	pg_end
	pop	rbx
	jmp	pg_commit_tx

cstring pg_msg_prepare, 'cannot prepare the statements'
cstring pg_msg_ready, 'database connection ready'

pg_prepare_message:
	cmp	al,'E'
	je	.error
	cmp	al,'Z'
	je	.ready
	ret					; ParseComplete, notices
.error:
	call	pg_log_error
	lea	rsi,[pg_msg_prepare]
	mov	edx,pg_msg_prepare.len
	jmp	pg_fail
.ready:
	mov	dword [r13+PG_STATE],PGS_READY
	mov	dword [r13+PG_BACKOFF],PG_BACKOFF_MIN
	lea	eax,[r14+r15]			; the first query's reply starts here
	mov	[r13+PG_RESP],eax
	call	log_begin
	log_lit 'database connection '
	mov	eax,ebx
	call	log_u64
	log_lit ' ready'
	jmp	log_end

cstring pg_msg_unexpected, 'reply without a pending query'

; READY: ErrorResponse marks the current query failed; ReadyForQuery ends
; it. Everything in between (BindComplete, DataRow, CommandComplete) is
; read by the continuation from the [PG_RESP, end) range.
pg_ready_message:
	cmp	al,'E'
	je	.error
	cmp	al,'Z'
	je	.done
	ret
.error:
	or	dword [r13+PG_FLAGS],PGF_QUERY_ERROR
	jmp	pg_read_sqlstate
.done:
	mov	eax,[r13+PG_QHEAD]
	cmp	eax,[r13+PG_QTAIL]
	je	.unexpected
	mov	eax,PGR_OK
	test	dword [r13+PG_FLAGS],PGF_QUERY_ERROR
	jz	@f
	mov	eax,PGR_SQL_ERROR
	and	dword [r13+PG_FLAGS],not PGF_QUERY_ERROR
@@:
	mov	ecx,[r13+PG_RESP]
	lea	rsi,[r13+PG_RX+rcx]
	lea	edx,[r14+r15]			; end of this ReadyForQuery
	mov	[r13+PG_RESP],edx
	lea	rdx,[r13+PG_RX+rdx]
	jmp	pg_deliver
.unexpected:
	lea	rsi,[pg_msg_unexpected]
	mov	edx,pg_msg_unexpected.len
	jmp	pg_fail

; rsi = ErrorResponse body, edx = length: copy the SQLSTATE ('C' field).
pg_read_sqlstate:
	lea	rdi,[rsi+rdx]
.field:
	cmp	rsi,rdi
	jae	.done
	lodsb
	test	al,al
	jz	.done
	cmp	al,'C'
	jne	.skip
	lea	rax,[rsi+5]
	cmp	rax,rdi
	ja	.done
	mov	eax,[rsi]
	mov	[r13+PG_SQLSTATE],eax
	mov	al,[rsi+4]
	mov	[r13+PG_SQLSTATE+4],al
.skip:
	cmp	rsi,rdi
	jae	.done
	lodsb
	test	al,al
	jnz	.skip
	jmp	.field
.done:
	ret

; Log the SQLSTATE and message of an ErrorResponse (handshake only; query
; errors are expected outcomes and go to the continuation instead).
pg_log_error:
	push	rsi
	push	rdx
	call	pg_read_sqlstate
	call	log_begin
	log_lit 'database error '
	lea	rsi,[r13+PG_SQLSTATE]
	mov	edx,5
	call	log_str
	pop	rdx
	pop	rsi
	lea	rdi,[rsi+rdx]
.field:
	cmp	rsi,rdi
	jae	.end
	lodsb
	test	al,al
	jz	.end
	mov	ah,al
	mov	rdx,rsi
.value:
	cmp	rsi,rdi
	jae	.end
	lodsb
	test	al,al
	jnz	.value
	cmp	ah,'M'
	jne	.field
	push	rsi
	push	rdi
	mov	rcx,rsi
	sub	rcx,rdx
	dec	rcx
	push	rcx
	push	rdx
	log_lit ': '
	pop	rsi
	pop	rdx
	call	log_str
	pop	rdi
	pop	rsi
	jmp	.field
.end:
	jmp	log_end

; ---------------------------------------------------------------- queries

; Hand a finished query to its continuation.
; r13 = connection, eax = PGR_xxx, rsi = first reply message, rdx = end.
; The continuation runs with rbx = HTTP slot, r12 = HTTP connection,
; rsi/rdx = reply range, eax = status, ecx = context (id + 1, or 0);
; afterwards the HTTP connection resumes parsing. Replies for connections
; that went away are dropped, and their context is released.
pg_deliver:
	push	rbx
	push	r12
	push	r14
	push	r15
	mov	r14,rsi
	mov	r15,rdx
	mov	r8d,eax
	cmp	eax,PGR_SQL_ERROR
	jne	@f
	metric_inc M_DB_ERRORS
@@:
	cmp	eax,PGR_UNAVAILABLE
	jne	@f
	metric_inc M_DB_UNAVAILABLE
@@:
	mov	eax,[r13+PG_QHEAD]
	mov	ecx,eax
	and	ecx,PG_MAX_INFLIGHT - 1
	shl	ecx,4
	lea	r9,[r13+PG_QUEUE+rcx]
	inc	eax
	mov	[r13+PG_QHEAD],eax
	mov	ebx,[r9+PQ_SLOT]
	mov	r10d,[r9+PQ_CTX]
	cmp	ebx,[g_max_conns]
	jae	.dropped
	conn_ptr r12,rbx
	mov	eax,[r9+PQ_GEN]
	cmp	[r12+C_GEN],eax
	jne	.dropped
	cmp	dword [r12+C_STATE],CS_OPEN
	jne	.dropped
	test	dword [r12+C_FLAGS],F_WAIT_DB
	jz	.dropped
	; Cleared before the continuation, which may wait again (another
	; query, a password hash).
	and	dword [r12+C_FLAGS],not F_WAIT_DB
	mov	eax,[r13+PG_SQLSTATE]
	mov	dword [g_pg_sqlstate],eax
	mov	al,[r13+PG_SQLSTATE+4]
	mov	byte [g_pg_sqlstate+4],al
	mov	r11d,[r9+PQ_CONT]
	mov	ecx,r10d
	mov	rsi,r14
	mov	rdx,r15
	mov	eax,r8d
	push	r13
	call	qword [pg_cont_tbl+r11*8]
	call	http_resume
	pop	r13
	jmp	.done
.dropped:
	mov	edi,r10d
	call	auth_ctx_free
.done:
	pop	r15
	pop	r14
	pop	r12
	pop	rbx
	ret

DB_BACKGROUND	= -1		; rbx for a query no request waits for

; Run a prepared statement for the current HTTP request.
; rbx = HTTP slot (or DB_BACKGROUND: then r12 is unused and the reply is
; dropped), r12 = HTTP connection, edi = STMT_xxx, esi = CONT_xxx,
; rdx = parameters (16 bytes each: dq pointer, dd length or -1 for NULL),
; ecx = parameter count, r8d = context (id + 1, or 0) handed back to the
; continuation.
; eax = 0 when queued (the connection waits, F_WAIT_DB), -1 when no
; database connection can take it right now (answer 503).
db_query:
	push	r13
	push	r14
	push	r15
	push	rbp
	push	r8				; the context, until it is queued
	mov	r14d,edi
	mov	r15d,esi
	mov	rbp,rdx
	mov	r9d,ecx
	cmp	dword [g_db_enabled],0
	je	.unavailable

	; Round robin over ready connections with room in their queue.
	xor	r10d,r10d
.pick:
	cmp	r10d,[g_pg_count]
	jae	.unavailable
	mov	eax,[g_pg_next]
	add	eax,r10d
	xor	edx,edx
	div	dword [g_pg_count]
	inc	r10d
	mov	r11d,edx
	pg_ptr	r13,r11d
	cmp	dword [r13+PG_STATE],PGS_READY
	jne	.pick
	mov	eax,[r13+PG_QTAIL]
	sub	eax,[r13+PG_QHEAD]
	cmp	eax,PG_MAX_INFLIGHT
	jae	.pick
	; Room for Bind + Execute + Sync?
	mov	eax,64
	xor	ecx,ecx
.size:
	cmp	ecx,r9d
	jae	.sized
	mov	edx,ecx
	shl	edx,4
	mov	edx,[rbp+rdx+8]
	test	edx,edx
	js	@f
	add	eax,edx
@@:
	add	eax,4
	inc	ecx
	jmp	.size
.sized:
	mov	ecx,PG_TX_CAP
	sub	ecx,[r13+PG_TX_LEN]
	cmp	eax,ecx
	ja	.pick
	lea	eax,[r11+1]
	mov	[g_pg_next],eax

	mov	eax,[r13+PG_TX_LEN]
	lea	rdi,[r13+PG_TX+rax]
	pg_begin 'B'
	mov	byte [rdi],0			; unnamed portal
	inc	rdi
	mov	eax,r14d
	shl	eax,5
	pg_bytes [pg_stmt_tbl+rax], [pg_stmt_tbl+rax+8]
	pg_be16	0				; parameters: all text
	mov	eax,r9d
	xchg	al,ah
	mov	[rdi],ax
	add	rdi,2
	xor	edx,edx
.parameter:
	cmp	edx,r9d
	jae	.parameters_done
	mov	eax,edx
	shl	eax,4
	mov	rsi,[rbp+rax]
	mov	ecx,[rbp+rax+8]
	mov	eax,ecx
	bswap	eax
	mov	[rdi],eax
	add	rdi,4
	test	ecx,ecx
	js	@f				; NULL: length -1, no bytes
	rep	movsb
@@:
	inc	edx
	jmp	.parameter
.parameters_done:
	pg_be16	0				; results: all text
	pg_end
	pg_begin 'E'
	mov	byte [rdi],0
	mov	dword [rdi+1],0			; no row limit
	add	rdi,5
	pg_end
	pg_begin 'S'
	pg_end

	; Queue the waiter. An empty queue restarts the reply timeout.
	mov	eax,[r13+PG_QTAIL]
	cmp	eax,[r13+PG_QHEAD]
	jne	@f
	mov	ecx,[g_tick]
	mov	[r13+PG_SINCE],ecx
@@:
	mov	ecx,eax
	and	ecx,PG_MAX_INFLIGHT - 1
	shl	ecx,4
	lea	rsi,[r13+PG_QUEUE+rcx]
	mov	[rsi+PQ_SLOT],ebx
	mov	[rsi+PQ_CONT],r15d
	mov	ecx,[rsp]
	mov	[rsi+PQ_CTX],ecx
	inc	eax
	mov	[r13+PG_QTAIL],eax
	mov	dword [rsi+PQ_GEN],0
	cmp	ebx,DB_BACKGROUND
	je	@f				; nobody waits: the reply is dropped
	mov	ecx,[r12+C_GEN]
	mov	[rsi+PQ_GEN],ecx
	or	dword [r12+C_FLAGS],F_WAIT_DB
@@:

	push	rbx
	mov	ebx,r11d
	call	pg_commit_tx
	pop	rbx
	metric_inc M_DB_QUERIES
	xor	eax,eax
	jmp	.done
.unavailable:
	metric_inc M_DB_UNAVAILABLE
	mov	eax,-1
.done:
	pop	r8
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	ret

; ---------------------------------------------------------------- failures

; Log "database connection N: <reason>" (r14 = -errno, or >= 0 for none).
; rsi = reason, edx = length.
pg_log_failure:
	push	rsi
	push	rdx
	call	log_begin
	log_lit 'database connection '
	mov	eax,ebx
	call	log_u64
	log_lit ': '
	pop	rdx
	pop	rsi
	call	log_str
	test	r14d,r14d
	jns	log_end
	log_lit ' (errno '
	mov	eax,r14d
	neg	eax
	call	log_u64
	log_lit ')'
	jmp	log_end

; Take the connection down: answer every waiting request with 503, cancel
; its I/O, and reconnect after the backoff once nothing references it.
; ebx = index, r13 = connection, rsi = reason, edx = length, r14 = errno.
pg_fail:
	cmp	dword [r13+PG_STATE],PGS_BROKEN
	je	.done
	cmp	dword [r13+PG_STATE],PGS_IDLE
	je	.done
	call	pg_log_failure
	mov	dword [r13+PG_STATE],PGS_BROKEN
.waiters:
	mov	eax,[r13+PG_QHEAD]
	cmp	eax,[r13+PG_QTAIL]
	je	.cancel
	mov	eax,PGR_UNAVAILABLE
	xor	esi,esi
	xor	edx,edx
	call	pg_deliver
	jmp	.waiters
.cancel:
	cmp	dword [r13+PG_PENDING],0
	je	pg_close
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ASYNC_CANCEL
	mov	byte [rax+SQE_FLAGS],IOSQE_CQE_SKIP_SUCCESS
	mov	ecx,[r13+PG_FD]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_OP_FLAGS],IORING_ASYNC_CANCEL_ALL or IORING_ASYNC_CANCEL_FD
	mov	rcx,OP_IGNORE shl 32
	mov	[rax+SQE_USER_DATA],rcx
.done:
	ret

pg_release_if_idle:
	cmp	dword [r13+PG_STATE],PGS_BROKEN
	jne	.done
	cmp	dword [r13+PG_PENDING],0
	je	pg_close
.done:
	ret

pg_close:
	mov	edi,[r13+PG_FD]
	mov	eax,SYS_close
	syscall

; Arm the reconnect timer: backoff with up to 25% jitter, then double it.
pg_schedule_retry:
	mov	dword [r13+PG_STATE],PGS_IDLE
	mov	dword [r13+PG_FLAGS],0
	cmp	dword [g_draining],0
	jne	.done
	mov	ecx,[r13+PG_BACKOFF]		; ms
	mov	r8d,ecx
	shr	r8d,2
	inc	r8d				; jitter range: a quarter of it
	rdtsc					; low bits are noise enough here
	xor	edx,edx
	div	r8d
	add	ecx,edx
	mov	eax,ecx
	xor	edx,edx
	mov	r8d,1000
	div	r8d
	mov	[r13+PG_TS],rax			; seconds
	imul	edx,edx,1000000
	mov	[r13+PG_TS+8],rdx		; nanoseconds
	mov	eax,[r13+PG_BACKOFF]
	add	eax,eax
	cmp	eax,PG_BACKOFF_MAX
	jbe	@f
	mov	eax,PG_BACKOFF_MAX
@@:
	mov	[r13+PG_BACKOFF],eax
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_TIMEOUT
	lea	rcx,[r13+PG_TS]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],1
	mov	rcx,OP_PG_TIMER shl 32
	or	rcx,rbx
	mov	[rax+SQE_USER_DATA],rcx
	inc	dword [r13+PG_PENDING]
.done:
	ret

on_pg_timer:
	pg_ptr	r13,ebx
	dec	dword [r13+PG_PENDING]
	cmp	dword [r13+PG_STATE],PGS_IDLE
	jne	.done
	cmp	dword [g_draining],0
	jne	.done
	jmp	pg_connect
.done:
	ret

cstring pg_msg_handshake_timeout, 'handshake timed out'
cstring pg_msg_query_timeout, 'no reply for the pending queries'

; Once per tick: give up on stuck handshakes and silent connections.
pg_tick:
	cmp	dword [g_db_enabled],0
	je	.done
	push	rbx
	push	r13
	push	r14
	xor	ebx,ebx
.each:
	cmp	ebx,[g_pg_count]
	jae	.finished
	pg_ptr	r13,ebx
	call	pg_trim
	mov	r14d,1				; no errno to report
	mov	eax,[g_tick]
	sub	eax,[r13+PG_SINCE]
	mov	ecx,[r13+PG_STATE]
	cmp	ecx,PGS_READY
	je	.ready
	cmp	ecx,PGS_CONNECTING
	jb	.next
	cmp	ecx,PGS_PREPARING
	ja	.next
	cmp	eax,PG_HANDSHAKE_TIMEOUT
	jb	.next
	lea	rsi,[pg_msg_handshake_timeout]
	mov	edx,pg_msg_handshake_timeout.len
	call	pg_fail
	jmp	.next
.ready:
	mov	ecx,[r13+PG_QHEAD]
	cmp	ecx,[r13+PG_QTAIL]
	je	.next
	cmp	eax,PG_QUERY_TIMEOUT
	jb	.next
	lea	rsi,[pg_msg_query_timeout]
	mov	edx,pg_msg_query_timeout.len
	call	pg_fail
.next:
	inc	ebx
	jmp	.each
.finished:
	pop	r14
	pop	r13
	pop	rbx
.done:
	ret

; Buffers that grew past their warm size give the rest back once they
; have stayed below it for g_trim_idle seconds. Only memory past the data
; is released: a send covers [PG_TX_SENT, PG_TX_LEN) and a receive writes
; past PG_RX_LEN, where pages simply fault in again. r13 = connection.
pg_trim:
	test	dword [r13+PG_GREW],1
	jz	.rx
	cmp	dword [r13+PG_TX_LEN],PG_TX_WARM
	ja	.rx
	mov	eax,[g_tick]
	sub	eax,[r13+PG_TX_PEAK]
	cmp	eax,[g_trim_idle]
	jb	.rx
	lea	rdi,[r13+PG_TX+PG_TX_WARM]
	mov	esi,PG_TX_CAP - PG_TX_WARM
	mov	edx,MADV_DONTNEED
	mov	eax,SYS_madvise
	syscall
	metric_add M_RETURNED, rsi
	and	dword [r13+PG_GREW],not 1
.rx:
	test	dword [r13+PG_GREW],2
	jz	.done
	cmp	dword [r13+PG_RX_LEN],PG_RX_WARM
	ja	.done
	mov	eax,[g_tick]
	sub	eax,[r13+PG_RX_PEAK]
	cmp	eax,[g_trim_idle]
	jb	.done
	lea	rdi,[r13+PG_RX+PG_RX_WARM]
	mov	esi,PG_RX_CAP - PG_RX_WARM
	mov	edx,MADV_DONTNEED
	mov	eax,SYS_madvise
	syscall
	metric_add M_RETURNED, rsi
	and	dword [r13+PG_GREW],not 2
.done:
	ret

; Reply rows. A reply range holds BindComplete, DataRows, CommandComplete
; and ReadyForQuery (no RowDescription: statements are prepared).

; First DataRow at or after rsi, before rdx. rsi = that message; CF when
; there is none. Only rax is clobbered.
pg_find_row:
	lea	rax,[rsi+5]
	cmp	rax,rdx
	ja	.none
	cmp	byte [rsi],'D'
	je	.found
	mov	eax,[rsi+1]
	bswap	eax
	lea	rsi,[rsi+rax+1]
	jmp	pg_find_row
.found:
	clc
	ret
.none:
	stc
	ret

; rsi = message: advance rsi past it.
pg_skip_message:
	mov	eax,[rsi+1]
	bswap	eax
	lea	rsi,[rsi+rax+1]
	ret

; Column ecx of the DataRow at rsi (preserved). rax = value, edx = length;
; CF when the value is NULL or there is no such column.
pg_field:
	push	rsi
	movzx	edx,word [rsi+5]
	xchg	dl,dh
	cmp	ecx,edx
	jae	.none
	add	rsi,7
.column:
	mov	eax,[rsi]
	bswap	eax
	add	rsi,4
	test	ecx,ecx
	jz	.found
	test	eax,eax
	js	@f				; NULL: no bytes follow
	add	rsi,rax
@@:
	dec	ecx
	jmp	.column
.found:
	test	eax,eax
	js	.none
	mov	edx,eax
	mov	rax,rsi
	pop	rsi
	clc
	ret
.none:
	pop	rsi
	stc
	ret

; Column ecx of the first DataRow in rsi..rdx: rax = value, edx = length;
; CF when there is no row or the value is NULL.
pg_row_field:
	call	pg_find_row
	jc	.done
	jmp	pg_field
.done:
	ret

; rax = connections ready.
db_ready_count:
	xor	eax,eax
	cmp	dword [g_db_enabled],0
	je	.done
	xor	ecx,ecx
.each:
	cmp	ecx,[g_pg_count]
	jae	.done
	imul	edx,ecx,PG_SIZE
	cmp	dword [g_pg+rdx+PG_STATE],PGS_READY
	jne	@f
	inc	eax
@@:
	inc	ecx
	jmp	.each
.done:
	ret

; eax = 1 when at least one connection is ready.
db_ready:
	xor	eax,eax
	cmp	dword [g_db_enabled],0
	je	.done
	xor	ecx,ecx
.each:
	cmp	ecx,[g_pg_count]
	jae	.done
	imul	edx,ecx,PG_SIZE
	cmp	dword [g_pg+rdx+PG_STATE],PGS_READY
	je	.yes
	inc	ecx
	jmp	.each
.yes:
	mov	eax,1
.done:
	ret

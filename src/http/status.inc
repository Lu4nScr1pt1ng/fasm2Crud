; HTTP status lines and their default JSON bodies.
;
; http_status appends one 32-byte entry to status_tbl:
;   dq line, line length, default body, body length
; and defines the id used to index it (ST_xxx).

virtual at 0
	STATUS.buffer::
end virtual
STATUS.count = 0

macro http_status id*, line*, body*
	local l, b
	cstring l, line, 13, 10
	cstring b, body
	id := STATUS.count
	STATUS.count = STATUS.count + 1
	virtual STATUS.buffer
		dq l, l.len, b, b.len
	end virtual
end macro

http_status ST_200, 'HTTP/1.1 200 OK',				'{"status":"ok"}'
http_status ST_201, 'HTTP/1.1 201 Created',			'{}'
http_status ST_204, 'HTTP/1.1 204 No Content',			''
http_status ST_400, 'HTTP/1.1 400 Bad Request',			'{"error":"bad_request"}'
http_status ST_401, 'HTTP/1.1 401 Unauthorized',		'{"error":"unauthorized"}'
http_status ST_409, 'HTTP/1.1 409 Conflict',			'{"error":"conflict"}'
http_status ST_415, 'HTTP/1.1 415 Unsupported Media Type',	'{"error":"unsupported_media_type"}'
http_status ST_422, 'HTTP/1.1 422 Unprocessable Content',	'{"error":"invalid_body"}'
http_status ST_404, 'HTTP/1.1 404 Not Found',			'{"error":"not_found"}'
http_status ST_405, 'HTTP/1.1 405 Method Not Allowed',		'{"error":"method_not_allowed"}'
http_status ST_413, 'HTTP/1.1 413 Content Too Large',		'{"error":"payload_too_large"}'
http_status ST_431, 'HTTP/1.1 431 Request Header Fields Too Large', '{"error":"headers_too_large"}'
http_status ST_500, 'HTTP/1.1 500 Internal Server Error',	'{"error":"internal"}'
http_status ST_501, 'HTTP/1.1 501 Not Implemented',		'{"error":"not_implemented"}'
http_status ST_503, 'HTTP/1.1 503 Service Unavailable',	'{"error":"unavailable"}'
http_status ST_505, 'HTTP/1.1 505 HTTP Version Not Supported',	'{"error":"http_version_not_supported"}'

rodata
	align 8
	status_tbl:
	virtual STATUS.buffer
		load STATUS.data:$-$$ from $$
	end virtual
	db STATUS.data
end rodata

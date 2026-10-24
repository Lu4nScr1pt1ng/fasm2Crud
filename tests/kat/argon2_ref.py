"""Reference Argon2 through the system libargon2 (the RFC 9106 reference
implementation), via ctypes."""
import ctypes
import ctypes.util

_lib = ctypes.CDLL(ctypes.util.find_library("argon2") or "libargon2.so.1")


class _Context(ctypes.Structure):
    _fields_ = [
        ("out", ctypes.c_char_p), ("outlen", ctypes.c_uint32),
        ("pwd", ctypes.c_char_p), ("pwdlen", ctypes.c_uint32),
        ("salt", ctypes.c_char_p), ("saltlen", ctypes.c_uint32),
        ("secret", ctypes.c_char_p), ("secretlen", ctypes.c_uint32),
        ("ad", ctypes.c_char_p), ("adlen", ctypes.c_uint32),
        ("t_cost", ctypes.c_uint32), ("m_cost", ctypes.c_uint32),
        ("lanes", ctypes.c_uint32), ("threads", ctypes.c_uint32),
        ("version", ctypes.c_uint32),
        ("allocate_cbk", ctypes.c_void_p), ("free_cbk", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
    ]


_lib.argon2_ctx.argtypes = [ctypes.POINTER(_Context), ctypes.c_int]
_lib.argon2_ctx.restype = ctypes.c_int


def argon2(kind, t, m, p, outlen, pwd, salt, secret=b"", ad=b""):
    """kind: 0 = Argon2d, 1 = Argon2i, 2 = Argon2id. Returns the tag."""
    out = ctypes.create_string_buffer(outlen)
    ctx = _Context(ctypes.cast(out, ctypes.c_char_p), outlen,
                   pwd, len(pwd), salt, len(salt),
                   secret or None, len(secret), ad or None, len(ad),
                   t, m, p, p, 0x13, None, None, 0)
    rc = _lib.argon2_ctx(ctypes.byref(ctx), kind)
    if rc != 0:
        raise ValueError(f"argon2_ctx failed: {rc}")
    return out.raw

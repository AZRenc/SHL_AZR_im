import io
import os
import sys
import ast
import zlib
import base64
import random
import shutil
import marshal
import hashlib
import tempfile
import zipfile
from pathlib import Path

from .sm4 import encrypt_cbc, decrypt_cbc, SM4_SBOX, SM4_FK, SM4_CK
from .b91 import shll_enc, shll_dec
from .huffman import shll_compress, shll_decompress
from .ast_ops import shll_transform
from .elf import shll_build

AZR_USER = '@AZR_hk'
AZR_TAG = 'lshlhom by AZR ' + AZR_USER
STAGE_VERSION = '1.1.0'
DEFAULT_SIZE_KB = 800
DEFAULT_SUFFIX = '_shlhom_azr.py'
PAYLOAD_ENTRY = 'payload.shlbin'
HASH_ENTRY = 'payload.sha256'
LOADER_ENTRY = '__main__.py'
ENV_SCRIPT = 'SHLHOM_AZR_SCRIPT'

__all__ = [
    'ShlhomError', 'tshfer', 'protect', 'encrypt_source', 'pack_payload',
    'verify_launcher', 'AZR_USER', 'AZR_TAG', 'STAGE_VERSION',
    'DEFAULT_SIZE_KB', 'DEFAULT_SUFFIX',
]


class ShlhomError(Exception):
    pass


_LOADER_SRC = '''import os, sys, marshal, zipfile, tempfile, shutil, subprocess, hashlib, traceback

_AZR = "lshlhom protected by AZR @AZR_hk"
_ENTRY = "payload.shlbin"
_HASH = "payload.sha256"
_ENV = "SHLHOM_AZR_SCRIPT"


def _die(msg, code=1):
    sys.stderr.write("[lshlhom/AZR] " + msg + "\\n")
    sys.stderr.write("[lshlhom/AZR] " + _AZR + "\\n")
    sys.exit(code)


def _run_blob(blob, script):
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    if blob[:4] == b"\\x7fELF" or blob[:2] == b"MZ":
        env["PYTHONHOME"] = sys.prefix
        env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
        work = tempfile.mkdtemp(prefix="shlhom_azr_")
        try:
            target = os.path.join(work, "payload.bin")
            with open(target, "wb") as fh:
                fh.write(blob)
            os.chmod(target, 0o755)
            return subprocess.run([target], env=env).returncode
        finally:
            shutil.rmtree(work, ignore_errors=True)
    code = marshal.loads(blob)
    space = {
        "__name__": "__main__",
        "__file__": script,
        "__builtins__": __builtins__,
        "__spec__": None,
        "__loader__": None,
        "__package__": None,
        "__doc__": None,
    }
    sys.argv = [script] + list(sys.argv[1:])
    exec(code, space)
    return 0


def _main():
    origin = os.path.abspath(sys.argv[0])
    if not zipfile.is_zipfile(origin):
        _die("payload container is not readable")
    with zipfile.ZipFile(origin, "r") as zf:
        names = zf.namelist()
        if _HASH not in names or _ENTRY not in names:
            _die("payload container is incomplete")
        want = zf.read(_HASH).decode("ascii", "ignore").strip()
        blob = zf.read(_ENTRY)
    if hashlib.sha256(blob).hexdigest() != want:
        _die("integrity check failed, this file was modified")
    script = os.environ.get(_ENV) or origin
    os.environ[_ENV] = script
    try:
        sys.exit(_run_blob(blob, script))
    except SystemExit:
        raise
    except BaseException:
        traceback.print_exc()
        sys.stderr.write("[lshlhom/AZR] the protected program stopped with an error\\n")
        sys.exit(1)


if __name__ == "__main__":
    _main()
'''

_LAUNCHER_SRC = '''import os, io, sys, stat, base64, shutil, zipfile, hashlib, tempfile, subprocess

_AZR = "lshlhom protected by AZR @AZR_hk"
_TOKEN = "{token}"
_B64 = "{payload}"
_ROOT = "shlhom_azr"
_ENV = "SHLHOM_AZR_SCRIPT"


def _die(msg, code=1):
    sys.stderr.write("[lshlhom/AZR] " + msg + "\\n")
    sys.stderr.write("[lshlhom/AZR] " + _AZR + "\\n")
    sys.exit(code)


def _self_path():
    try:
        if __file__:
            return os.path.abspath(__file__)
    except NameError:
        pass
    for cand in sys.argv:
        if cand and os.path.isfile(cand):
            return os.path.abspath(cand)
    return ""


def _purge(path):
    if not os.path.isdir(path):
        return
    for base, dirs, files in os.walk(path, topdown=False):
        for name in files:
            try:
                target = os.path.join(base, name)
                os.chmod(target, stat.S_IWRITE)
                os.remove(target)
            except OSError:
                pass
        for name in dirs:
            try:
                os.rmdir(os.path.join(base, name))
            except OSError:
                pass
    try:
        os.rmdir(path)
    except OSError:
        pass


def _main():
    me = _self_path()
    if not me:
        _die("cannot resolve the path of this file")
    if hashlib.sha256(_B64.encode("ascii", "ignore")).hexdigest()[:24] != _TOKEN:
        _die("integrity check failed, this file was modified")
    try:
        blob = base64.b64decode(_B64, validate=True)
    except Exception:
        _die("payload is corrupted")
    if not zipfile.is_zipfile(io.BytesIO(blob)):
        _die("payload is corrupted")
    home = os.path.expanduser("~")
    if not home or home == "~":
        home = tempfile.gettempdir()
    root = os.path.join(home, "." + _ROOT)
    run = None
    try:
        try:
            os.makedirs(root, mode=0o700, exist_ok=True)
            run = tempfile.mkdtemp(prefix="run_", dir=root)
        except OSError:
            run = tempfile.mkdtemp(prefix="shlhom_azr_")
        target = os.path.join(run, "container.zip")
        with open(target, "wb") as fh:
            fh.write(blob)
        env = os.environ.copy()
        env[_ENV] = me
        env["PYTHONIOENCODING"] = "utf-8"
        py = sys.executable or "python3"
        try:
            code = subprocess.run([py, target], env=env).returncode
        except OSError as exc:
            _die("cannot start python: " + str(exc))
    finally:
        if run:
            shutil.rmtree(run, ignore_errors=True)
        _purge(root)
    sys.exit(code)


if __name__ == "__main__":
    _main()
'''

_STAGE_SRC = '''import sys, os, zlib, marshal

_AZR = "lshlhom protected by AZR @AZR_hk"
_ENV = "SHLHOM_AZR_SCRIPT"

_SHL_XOR_K1 = {x1}
_SHL_XOR_K2 = {x2}

_SHL_SM4_KEY = bytes.fromhex("{key}")
_SHL_SM4_IV = bytes.fromhex("{iv}")
_SHL_B91_DATA = "{b91}"

_SHL_SBOX = {sbox}
_SHL_FK = {fk}
_SHL_CK = {ck}


def _shl_lshift(x, n):
    return ((x << n) & 0xFFFFFFFF) | ((x >> (32 - n)) & 0xFFFFFFFF)


def _shl_sbox(b):
    return _SHL_SBOX[b]


def _shl_t(x):
    b = [_shl_sbox((x >> 24) & 0xFF), _shl_sbox((x >> 16) & 0xFF), _shl_sbox((x >> 8) & 0xFF), _shl_sbox(x & 0xFF)]
    y = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
    return y ^ _shl_lshift(y, 2) ^ _shl_lshift(y, 10) ^ _shl_lshift(y, 18) ^ _shl_lshift(y, 24)


def _shl_t_prime(x):
    b = [_shl_sbox((x >> 24) & 0xFF), _shl_sbox((x >> 16) & 0xFF), _shl_sbox((x >> 8) & 0xFF), _shl_sbox(x & 0xFF)]
    y = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
    return y ^ _shl_lshift(y, 13) ^ _shl_lshift(y, 23)


def _shl_ks(k):
    mk = [(k[0] << 24) | (k[1] << 16) | (k[2] << 8) | k[3], (k[4] << 24) | (k[5] << 16) | (k[6] << 8) | k[7], (k[8] << 24) | (k[9] << 16) | (k[10] << 8) | k[11], (k[12] << 24) | (k[13] << 16) | (k[14] << 8) | k[15]]
    kk = [mk[i] ^ _SHL_FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        kk.append(kk[-4] ^ _shl_t_prime(kk[-3] ^ kk[-2] ^ kk[-1] ^ _SHL_CK[i]))
        rk.append(kk[-1])
    return rk


def _shl_eb(blk, rk):
    x = [(blk[0] << 24) | (blk[1] << 16) | (blk[2] << 8) | blk[3], (blk[4] << 24) | (blk[5] << 16) | (blk[6] << 8) | blk[7], (blk[8] << 24) | (blk[9] << 16) | (blk[10] << 8) | blk[11], (blk[12] << 24) | (blk[13] << 16) | (blk[14] << 8) | blk[15]]
    for i in range(32):
        x.append(x[-4] ^ _shl_t(x[-3] ^ x[-2] ^ x[-1] ^ rk[i]))
    out = [x[35], x[34], x[33], x[32]]
    res = bytearray()
    for v in out:
        res.extend(((v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF))
    return bytes(res)


def _shl_dec_ecb(k, c):
    rk = _shl_ks(k)[::-1]
    res = bytearray()
    for i in range(0, len(c), 16):
        res.extend(_shl_eb(c[i:i + 16], rk))
    return bytes(res)


def _shl_dec_cbc(k, iv, c):
    if len(c) % 16:
        raise ValueError("cipher length is broken")
    prev = iv
    plain = bytearray()
    for i in range(0, len(c), 16):
        enc = c[i:i + 16]
        dec = _shl_dec_ecb(k, enc)
        plain.extend(bytes(a ^ b for a, b in zip(dec, prev)))
        prev = enc
    if not plain:
        return b""
    pad = plain[-1]
    if pad < 1 or pad > 16 or bytes(plain[-pad:]) != bytes([pad]) * pad:
        raise ValueError("padding check failed")
    return bytes(plain[:-pad])


_SHL_ALPH = "".join(chr(i) for i in range(33, 127) if chr(i) not in {{'"', "'", "\\\\"}})
_SHL_DEC = {{c: i for i, c in enumerate(_SHL_ALPH)}}


def _shl_b91_decode(s):
    v = -1
    b = 0
    n = 0
    out = bytearray()
    for ch in s:
        if ch not in _SHL_DEC:
            continue
        c = _SHL_DEC[ch]
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n >= 8:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1
    if v >= 0:
        out.append((b | (v << n)) & 255)
    return bytes(out)


def _shl_huff_de(data, pos=0):
    if pos >= len(data):
        raise ValueError("huffman tree is broken")
    if data[pos] == 1:
        if pos + 1 >= len(data):
            raise ValueError("huffman tree is broken")
        return (data[pos + 1], pos + 2)
    left, pos = _shl_huff_de(data, pos + 1)
    right, pos = _shl_huff_de(data, pos)
    return (left, right), pos


def _shl_huff_decompress(data):
    tl = int.from_bytes(data[:2], "big")
    ol = int.from_bytes(data[2:6], "big")
    if tl == 0 and ol == 0:
        return b""
    tb = data[6:6 + tl]
    db = data[6 + tl:]
    root, _ = _shl_huff_de(tb, 0)
    if ol == 0:
        return b""
    if isinstance(root, int):
        return bytes([root]) * ol
    result = bytearray()
    node = root
    for byte in db:
        for bit in range(7, -1, -1):
            node = node[1] if ((byte >> bit) & 1) else node[0]
            if isinstance(node, int):
                result.append(node)
                if len(result) == ol:
                    return bytes(result)
                node = root
    raise ValueError("huffman stream is truncated")


def _shl_dec_str(enc):
    return _shl_dec_cbc(_SHL_SM4_KEY, enc[:16], enc[16:]).decode("utf-8")


def _shl_dec_bytes(enc):
    return _shl_dec_cbc(_SHL_SM4_KEY, enc[:16], enc[16:])


_shl_a = _shl_b91_decode(_SHL_B91_DATA)
_shl_b = _shl_huff_decompress(_shl_a)
_shl_c = _shl_dec_cbc(_SHL_SM4_KEY, _SHL_SM4_IV, _shl_b)
_shl_d = bytes([b ^ _SHL_XOR_K1 for b in bytes([b ^ _SHL_XOR_K2 for b in _shl_c])])
_shl_code = marshal.loads(zlib.decompress(_shl_d))
_shl_script = os.environ.get(_ENV) or sys.argv[0]
globals()["__file__"] = _shl_script
globals()["__name__"] = "__main__"
sys.argv[0] = _shl_script
exec(_shl_code, globals())
'''


def _rand_byte():
    return random.SystemRandom().randint(0x10, 0xFF)


def _seeded(seed, label, length):
    out = b''
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f'{seed}|{label}|{counter}'.encode()).digest()
        counter += 1
    return out[:length]


def _build_stage_code(key, iv, xor1, xor2, b91):
    return _STAGE_SRC.format(
        x1=xor1,
        x2=xor2,
        key=key.hex(),
        iv=iv.hex(),
        b91=b91,
        sbox=repr(SM4_SBOX),
        fk=repr(SM4_FK),
        ck=repr(SM4_CK),
    )


def _verify_chain(key, iv, xor1, xor2, meta, compiled):
    if shll_dec(meta['b91']) != meta['huff']:
        raise ShlhomError('base91 layer verification failed')
    if shll_decompress(meta['huff']) != meta['sm4']:
        raise ShlhomError('huffman layer verification failed')
    if decrypt_cbc(key, iv, meta['sm4']) != meta['xored']:
        raise ShlhomError('sm4 layer verification failed')
    restored = bytes([b ^ xor1 for b in bytes([b ^ xor2 for b in meta['xored']])])
    try:
        back = marshal.loads(zlib.decompress(restored))
    except Exception as exc:
        raise ShlhomError(f'marshal layer verification failed: {exc}') from exc
    if back.co_code != compiled.co_code or back.co_names != compiled.co_names:
        raise ShlhomError('bytecode verification failed')
    return True


def encrypt_source(source, size_kb=DEFAULT_SIZE_KB, obfuscate=True,
                    rename_defs=False, strict=True, seed=None, pad=True,
                    verbose=False):
    if not isinstance(source, str):
        raise ShlhomError('source must be str')
    if '\x00' in source:
        raise ShlhomError('source contains null bytes')
    if seed is None:
        key = os.urandom(16)
        iv = os.urandom(16)
        xor1 = _rand_byte()
        xor2 = _rand_byte()
    else:
        key = _seeded(seed, 'key', 16)
        iv = _seeded(seed, 'iv', 16)
        xor1 = _seeded(seed, 'x1', 1)[0] or 0x5A
        xor2 = _seeded(seed, 'x2', 1)[0] or 0xA5

    working = source
    if obfuscate:
        try:
            working = shll_transform(source, key, rename_defs=rename_defs)
        except (SyntaxError, ValueError, TypeError, RecursionError,
                MemoryError, NotImplementedError) as exc:
            if strict:
                raise ShlhomError(
                    'ast obfuscation failed: '
                    f'{type(exc).__name__}: {exc}'
                ) from exc
            if verbose:
                sys.stderr.write(
                    '[lshlhom/AZR] ast obfuscation skipped: '
                    f'{type(exc).__name__}: {exc}\n'
                )

    try:
        ast.parse(working)
    except SyntaxError as exc:
        raise ShlhomError(f'protected source does not parse: {exc}') from exc

    try:
        compiled = compile(working, '<shlhom_azr_core>', 'exec')
    except (SyntaxError, ValueError) as exc:
        raise ShlhomError(f'protected source does not compile: {exc}') from exc

    blob_marshal = marshal.dumps(compiled)
    blob_zlib = zlib.compress(blob_marshal, 9)
    blob_xored = bytes([b ^ xor2 for b in bytes([b ^ xor1 for b in blob_zlib])])
    blob_sm4 = encrypt_cbc(key, iv, blob_xored)
    blob_huff = shll_compress(blob_sm4)
    blob_b91 = shll_enc(blob_huff)

    meta = {
        'key': key, 'iv': iv, 'xor1': xor1, 'xor2': xor2,
        'b91': blob_b91, 'sm4': blob_sm4, 'huff': blob_huff,
        'xored': blob_xored, 'size_kb': size_kb, 'pad': pad,
    }
    _verify_chain(key, iv, xor1, xor2, meta, compiled)
    if verbose:
        sys.stderr.write(
            f'[lshlhom/AZR] layers verified, payload {len(blob_b91)} chars\n'
        )
    return _build_stage_code(key, iv, xor1, xor2, blob_b91), meta


def verify_launcher(launcher):
    try:
        compile(launcher, '<shlhom_azr_launcher>', 'exec')
    except SyntaxError as exc:
        raise ShlhomError(f'generated launcher is not valid python: {exc}') from exc
    start = launcher.index('_B64 = "') + len('_B64 = "')
    end = launcher.index('"', start)
    try:
        raw = base64.b64decode(launcher[start:end], validate=True)
    except Exception as exc:
        raise ShlhomError(f'generated container is not valid base64: {exc}') from exc
    if not raw:
        raise ShlhomError('generated container is empty')
    try:
        with zipfile.ZipFile(io.BytesIO(raw), 'r') as zf:
            names = set(zf.namelist())
            missing = {LOADER_ENTRY, HASH_ENTRY, PAYLOAD_ENTRY} - names
            if missing:
                raise ShlhomError(f'generated container misses {sorted(missing)}')
            want = zf.read(HASH_ENTRY).decode('ascii', 'ignore').strip()
            if hashlib.sha256(zf.read(PAYLOAD_ENTRY)).hexdigest() != want:
                raise ShlhomError('generated container hash mismatch')
            loader = zf.read(LOADER_ENTRY).decode('utf-8')
    except ShlhomError:
        raise
    except (zipfile.BadZipFile, OSError, EOFError, ValueError, KeyError) as exc:
        raise ShlhomError(f'generated container is damaged: {exc}') from exc
    compile(loader, '<shlhom_azr_loader>', 'exec')
    return True


def pack_payload(stage_code, size_kb=DEFAULT_SIZE_KB, pad=True, native=True,
                 verbose=False):
    work = Path(tempfile.mkdtemp(prefix='shlhom_azr_build_'))
    try:
        entry = work / PAYLOAD_ENTRY
        if native:
            mode = shll_build(stage_code, entry, size_kb if pad else 0)
        else:
            mode = shll_build(stage_code, entry, 0, native=False)
            if pad and size_kb and size_kb > 0:
                from .elf import _pad_file
                _pad_file(entry, size_kb)
        if not entry.exists():
            raise ShlhomError('payload build produced no output')
        blob = entry.read_bytes()

        container = work / 'container.zip'
        with zipfile.ZipFile(container, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            zf.writestr(LOADER_ENTRY, _LOADER_SRC)
            zf.writestr(HASH_ENTRY, hashlib.sha256(blob).hexdigest())
            zf.writestr(PAYLOAD_ENTRY, blob)

        raw = container.read_bytes()
        payload = base64.b64encode(raw).decode('ascii')
        token = hashlib.sha256(payload.encode('ascii')).hexdigest()[:24]
        launcher = _LAUNCHER_SRC.format(token=token, payload=payload)
        if verbose:
            sys.stderr.write(
                f'[lshlhom/AZR] payload mode: {mode}, '
                f'output: {len(launcher)} bytes\n'
            )
        return launcher
    finally:
        shutil.rmtree(work, ignore_errors=True)


def tshfer(shl_input, shl_output=None, shl_size_kb=DEFAULT_SIZE_KB, *,
           output=None, size_kb=None, obfuscate=True, rename_defs=False,
           strict=True, seed=None, pad=True, native=True, verify=True,
           verbose=False, suffix=DEFAULT_SUFFIX):
    if output is not None:
        shl_output = output
    if size_kb is not None:
        shl_size_kb = size_kb
    try:
        shl_size_kb = int(shl_size_kb)
    except (TypeError, ValueError):
        raise ShlhomError('size_kb must be a number') from None
    if shl_size_kb <= 0:
        shl_size_kb = DEFAULT_SIZE_KB

    path = Path(shl_input)
    if not path.exists() or not path.is_file():
        raise ShlhomError(f'file not found: {shl_input}')

    try:
        source = path.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError) as exc:
        raise ShlhomError(f'cannot read {shl_input}: {exc}') from exc

    stage, _meta = encrypt_source(
        source, size_kb=shl_size_kb, obfuscate=obfuscate,
        rename_defs=rename_defs, strict=strict, seed=seed, pad=pad,
        verbose=verbose,
    )
    launcher = pack_payload(stage, size_kb=shl_size_kb, pad=pad, native=native,
                            verbose=verbose)

    if verify:
        verify_launcher(launcher)

    if shl_output is None:
        target = path.parent / f'{path.stem}{suffix}'
    else:
        target = Path(shl_output)
    if str(target.parent) not in ('', '.'):
        target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + '.azrpart')
    tmp.write_text(launcher, encoding='utf-8')
    os.replace(tmp, target)
    if verbose:
        sys.stderr.write(
            f'[lshlhom/AZR] {AZR_TAG}\n'
            f'[lshlhom/AZR] wrote {target} ({target.stat().st_size} bytes)\n'
        )
    return str(target)


protect = tshfer

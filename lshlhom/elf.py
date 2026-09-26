import os
import sys
import shutil
import marshal
import subprocess
import sysconfig
import tempfile
from pathlib import Path


def _which(*names):
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _libpython_name():
    return f'python{sys.version_info[0]}.{sys.version_info[1]}'


def _libpython_dirs():
    found = []
    for key in ('LIBDIR', 'LIBPL', 'srcdir'):
        value = sysconfig.get_config_var(key)
        if value and value not in found:
            found.append(value)
    platlib = sysconfig.get_paths().get('platlib')
    if platlib and platlib not in found:
        found.append(platlib)
    return [d for d in found if d and os.path.isdir(d)]


def _config_flags():
    cfg = _which('python3-config', f'python{sys.version_info[0]}.{sys.version_info[1]}-config')
    flags = []
    if cfg:
        try:
            out = subprocess.run(
                [cfg, '--cflags', '--ldflags'],
                capture_output=True, text=True, timeout=60,
            )
            if out.returncode == 0 and out.stdout.strip():
                flags += out.stdout.split()
        except (OSError, subprocess.SubprocessError):
            pass
    if not any(f.startswith('-I') for f in flags):
        include = sysconfig.get_paths().get('include')
        if include:
            flags += ['-I', include]
    if not any(f == '-ldl' for f in flags):
        flags += ['-ldl', '-lm']

    name = _libpython_name()
    have_dir = None
    for cand in _libpython_dirs():
        for ext in ('.so', '.a', '.dylib'):
            if os.path.exists(os.path.join(cand, f'lib{name}{ext}')):
                have_dir = cand
                break
        if have_dir:
            break
    if have_dir and f'-L{have_dir}' not in flags:
        flags += ['-L', have_dir]
    if not any(f == f'-l{name}' for f in flags):
        flags += [f'-l{name}']
    return flags


def _link_variants():
    base = _config_flags()
    yield base
    yield base + ['-fno-stack-protector']
    yield base + ['-fno-stack-protector', '-lpthread', '-lutil']
    yield base + ['-Wl,--no-as-needed', '-Wl,--copy-dt-needed-entries']
    yield base + ['-fno-stack-protector', '-Wl,--no-as-needed', '-Wl,--copy-dt-needed-entries']


def _try_elf(code, out):
    cython = _which('cython', 'cython3')
    cc = _which('gcc', 'clang', 'cc')
    if not cython or not cc:
        return False
    work = Path(tempfile.mkdtemp(prefix='shlhom_azr_elf_'))
    try:
        src = work / 'shlhom_azr_loader.py'
        csrc = work / 'shlhom_azr_loader.c'
        src.write_text(code, encoding='utf-8')
        gen = subprocess.run(
            [cython, str(src), '--embed', '-3', '-o', str(csrc)],
            capture_output=True, timeout=900,
        )
        if gen.returncode != 0 or not csrc.exists():
            return False
        for extra in _link_variants():
            if out.exists():
                out.unlink()
            link = subprocess.run(
                [cc, '-o', str(out), str(csrc)] + list(extra) + ['-O2', '-w'],
                capture_output=True, timeout=900,
            )
            if link.returncode == 0 and out.exists() and out.stat().st_size > 0:
                break
        else:
            return False
        for strip_args in (['strip', '-s'], ['strip', '--strip-all']):
            tool = _which(*strip_args)
            if not tool:
                continue
            try:
                subprocess.run([tool, str(out)], capture_output=True, timeout=120)
            except (OSError, subprocess.SubprocessError):
                pass
        os.chmod(out, 0o755)
        return True
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    finally:
        shutil.rmtree(work, ignore_errors=True)



def _pad_file(out, size_kb):
    if not size_kb or size_kb <= 0:
        return 0
    have = out.stat().st_size
    want = int(size_kb) * 1024
    if have >= want:
        return 0
    with open(out, 'ab') as fh:
        fh.write(os.urandom(want - have))
    return want - have


def shll_build(code, out, size_kb=0, native=True):
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()

    if native and _try_elf(code, out):
        mode = 'elf'
    else:
        try:
            compiled = compile(code, '<shlhom_azr_payload>', 'exec')
        except (SyntaxError, ValueError) as exc:
            raise RuntimeError(f'payload does not compile: {exc}') from exc
        out.write_bytes(marshal.dumps(compiled))
        mode = 'marshal'

    _pad_file(out, size_kb)
    return mode

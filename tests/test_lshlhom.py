import io
import os
import sys
import ast
import unittest
import tempfile
import shutil
import textwrap
import zipfile
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lshlhom import __version__, ShlhomError, tshfer, protect
from lshlhom import core
from lshlhom.sm4 import encrypt_cbc, decrypt_cbc, encrypt_ecb, decrypt_ecb
from lshlhom.b91 import shll_enc, shll_dec
from lshlhom.huffman import shll_compress, shll_decompress
from lshlhom.ast_ops import shll_transform
from lshlhom.elf import shll_build

RUNTIME_BATTERY = [
    ('class_method', textwrap.dedent('''
        class A:
            def m(self):
                return 1
        assert A().m() == 1
        assert str(A).split('.')[1].startswith('A')
        print('ok class_method')
    ''')),
    ('class_attr', textwrap.dedent('''
        class A:
            X = 5
        assert A.X == 5
        print('ok class_attr')
    ''')),
    ('getattr_by_name', textwrap.dedent('''
        class A:
            def m(self):
                return 7
        assert getattr(A(), 'm')() == 7
        assert hasattr(A, 'm')
        print('ok getattr_by_name')
    ''')),
    ('super_init', textwrap.dedent('''
        class B:
            def __init__(self, v):
                self.v = v
        class C(B):
            def __init__(self, v):
                super().__init__(v)
            def get(self):
                return self.v
        assert C(3).get() == 3
        print('ok super_init')
    ''')),
    ('dataclass', textwrap.dedent('''
        from dataclasses import dataclass
        @dataclass
        class P:
            x: int
            y: str = 'd'
            def dbl(self):
                return self.x * 2
        assert P(2).dbl() == 4
        assert P(1).y == 'd'
        print('ok dataclass')
    ''')),
    ('func_ref', textwrap.dedent('''
        def helper(x):
            return x + 1
        f = helper
        assert f(1) == 2
        print('ok func_ref')
    ''')),
    ('dict_of_funcs', textwrap.dedent('''
        def a():
            return 1
        d = {'a': a}
        assert d['a']() == 1
        print('ok dict_of_funcs')
    ''')),
    ('global_stmt', textwrap.dedent('''
        cnt = 0
        def inc():
            global cnt
            cnt += 1
        inc()
        inc()
        assert cnt == 2
        print('ok global_stmt')
    ''')),
    ('nonlocal_stmt', textwrap.dedent('''
        def outer():
            n = 0
            def inner():
                nonlocal n
                n += 1
            inner()
            inner()
            return n
        assert outer() == 2
        print('ok nonlocal_stmt')
    ''')),
    ('exc_handler', textwrap.dedent('''
        try:
            1 / 0
        except ZeroDivisionError as e:
            assert type(e).__name__ == 'ZeroDivisionError'
        print('ok exc_handler')
    ''')),
    ('main_guard', textwrap.dedent('''
        def main():
            return 5
        if __name__ == '__main__':
            assert main() == 5
        print('ok main_guard')
    ''')),
    ('decorator_static', textwrap.dedent('''
        import functools
        def deco(fn):
            @functools.wraps(fn)
            def w(*a, **k):
                return fn(*a, **k) * 10
            return w
        @deco
        def val(x):
            return x
        class Holder:
            @staticmethod
            def s():
                return 's'
            @classmethod
            def c(cls):
                return cls.__name__
        assert val(2) == 20
        assert Holder.s() == 's'
        assert Holder.c() == 'Holder'
        print('ok decorator_static')
    ''')),
    ('match_stmt', textwrap.dedent('''
        def f(v):
            match v:
                case 'abc':
                    return 'str'
                case [a, *rest]:
                    return (a, rest)
                case {'k': x, **others}:
                    return (x, others)
                case 1 | 2:
                    return 'small'
                case _:
                    return None
        assert f('abc') == 'str'
        assert f([1, 2]) == (1, [2])
        assert f({'k': 9, 'z': 1}) == (9, {'z': 1})
        assert f(2) == 'small'
        assert f(3.5) is None
        print('ok match_stmt')
    ''')),
    ('comprehensions', textwrap.dedent('''
        data = [1, 2, 3]
        assert [i * 2 for i in data if i > 1] == [4, 6]
        assert {k: v for k, v in zip('ab', [1, 2])} == {'a': 1, 'b': 2}
        assert tuple(i for i in range(3)) == (0, 1, 2)
        assert sum(i for i in data) == 6
        print('ok comprehensions')
    ''')),
    ('loops_with', textwrap.dedent('''
        import io
        total = 0
        for i in range(5):
            if i % 2:
                continue
            total += i
        while total > 0:
            total -= 1
        assert total == 0
        buf = io.StringIO()
        buf.write('x')
        assert buf.getvalue() == 'x'
        print('ok loops_with')
    ''')),
    ('strings', textwrap.dedent('''
        import json
        data = {'k': [1, 2], 's': 'v'}
        assert json.loads(json.dumps(data)) == data
        assert f'{1 + 1}' == '2'
        assert 'a{}b'.format('c') == 'acb'
        assert 'x' in 'xyz'
        assert b'\\x00\\x01'.hex() == '0001'
        print('ok strings')
    ''')),
    ('nested_closures', textwrap.dedent('''
        def make(x):
            def add(y):
                def step(z):
                    return x + y + z
                return step
            return add
        assert make(1)(2)(3) == 6
        print('ok nested_closures')
    ''')),
    ('lambda_defaults', textwrap.dedent('''
        f = lambda a, b=2, *c, **d: (a, b, c, d)
        assert f(1, 3, 4, x=5) == (1, 3, (4,), {'x': 5})
        print('ok lambda_defaults')
    ''')),
    ('walrus', textwrap.dedent('''
        if (n := 5) > 1:
            assert n == 5
        assert [y for x in range(3) if (y := x * 2)] == [2, 4]
        print('ok walrus')
    ''')),
    ('module_docstring', textwrap.dedent('''
        import sys
        assert __doc__ is None or isinstance(__doc__, str)
        print('ok module_docstring')
    ''')),
]


def capture_output(fn, *args, **kwargs):
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        fn(*args, **kwargs)
    return buf.getvalue()


class TestSM4(unittest.TestCase):
    def test_kat_eb(self):
        key = bytes.fromhex('0123456789abcdeffedcba9876543210')
        expect = '681edf34d206965e86b3e94f536e4246'
        self.assertEqual(encrypt_ecb(key, key).hex(), expect)
        self.assertEqual(decrypt_ecb(key, bytes.fromhex(expect)), key)

    def test_cbc_roundtrip(self):
        key = os.urandom(16)
        iv = os.urandom(16)
        for size in (0, 1, 15, 16, 17, 100, 4096):
            plain = os.urandom(size)
            self.assertEqual(decrypt_cbc(key, iv, encrypt_cbc(key, iv, plain)), plain)

    def test_bad_args(self):
        with self.assertRaises(ValueError):
            encrypt_cbc(b'x', b'x', b'0123456789abcdef')
        with self.assertRaises(ValueError):
            encrypt_cbc(b'0' * 15, b'0' * 16, b'0' * 16)
        with self.assertRaises(ValueError):
            decrypt_cbc(b'0' * 16, b'0' * 16, b'0' * 15)

    def test_bad_padding(self):
        with self.assertRaises(ValueError):
            decrypt_cbc(b'0' * 16, b'0' * 16, b'\x00' * 16)


class TestBase91(unittest.TestCase):
    def test_roundtrip(self):
        for size in (0, 1, 2, 7, 8, 13, 64, 1000):
            data = os.urandom(size)
            self.assertEqual(shll_dec(shll_enc(data)), data)

    def test_ignores_bad_chars(self):
        data = os.urandom(32)
        self.assertEqual(shll_dec('\n\t \x00' + shll_enc(data)), data)


class TestHuffman(unittest.TestCase):
    def test_roundtrip(self):
        for payload in (b'', b'a', b'a' * 100, os.urandom(64),
                        bytes(range(256)) * 4, b'\x00' * 50):
            self.assertEqual(shll_decompress(shll_compress(payload)), payload)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            shll_decompress(b'')


class TestASTTransform(unittest.TestCase):
    def _roundtrip(self, source):
        key = os.urandom(16)
        out = shll_transform(textwrap.dedent(source), key)
        ast.parse(out)
        compile(out, '<t>', 'exec')
        return out

    def test_keeps_def_and_class_names(self):
        source = '''
            class Thing:
                pass
            def thing():
                return 1
        '''
        out = self._roundtrip(source)
        self.assertIn('class Thing', out)
        self.assertIn('def thing', out)

    def test_keeps_class_member_names(self):
        source = '''
            class Thing:
                VALUE = 1
                def run(self):
                    return self.VALUE
        '''
        out = self._roundtrip(source)
        self.assertIn('VALUE', out)
        self.assertIn('run', out)

    def test_keeps_imports_and_args(self):
        source = '''
            import os
            from sys import argv
            def fn(alpha, beta=2, *gamma, **delta):
                return alpha, beta, gamma, delta, os.sep, argv
        '''
        out = self._roundtrip(source)
        self.assertIn('import os', out)
        self.assertIn('alpha', out)
        self.assertIn('gamma', out)

    def test_keeps_builtin_and_dunder(self):
        source = '''
            def fn(value):
                return repr(value), len(value), __name__
        '''
        out = self._roundtrip(source)
        self.assertIn('repr', out)
        self.assertIn('len', out)

    def test_encrypts_string_literals(self):
        source = '''
            def fn():
                return "secret text"
        '''
        out = self._roundtrip(source)
        self.assertNotIn('secret text', out)
        self.assertIn('_shl_dec_str', out)

    def test_keeps_match_patterns_literal(self):
        source = '''
            def fn(v):
                match v:
                    case "abc":
                        return 1
                    case {"k": x}:
                        return x
                    case _:
                        return 0
        '''
        out = self._roundtrip(source)
        self.assertNotIn('_shl_dec_str(b', out.split('case')[1].split(':')[0])

    def test_rename_defs_option(self):
        source = 'def alpha():\n    return 1\n'
        key = os.urandom(16)
        kept = shll_transform(source, key, rename_defs=False)
        self.assertIn('alpha', kept)
        renamed = shll_transform(source, key, rename_defs=True)
        self.assertNotIn('alpha', renamed)

    def test_flatten(self):
        source = '''
            def fn(n):
                total = 0
                for i in range(n):
                    total += i
                return total
        '''
        out = self._roundtrip(source)
        self.assertIn('while', out)

    def test_syntax_error_raises(self):
        with self.assertRaises(SyntaxError):
            shll_transform('def (', os.urandom(16))


class TestEncryptSource(unittest.TestCase):
    def test_roundtrip_all_battery(self):
        for name, source in RUNTIME_BATTERY:
            with self.subTest(name=name):
                stage, meta = core.encrypt_source(source)
                self.assertTrue(stage.startswith('import sys, os, zlib, marshal'))
                out = capture_output(exec, stage, {'__name__': '__main__'})
                self.assertIn('ok ' + name, out)

    def test_layers_verified(self):
        stage, meta = core.encrypt_source('print(1)')
        self.assertEqual(len(meta['key']), 16)
        self.assertEqual(len(meta['iv']), 16)
        core._verify_chain(meta['key'], meta['iv'], meta['xor1'],
                           meta['xor2'], meta, compile('print(1)', '<x>', 'exec'))

    def test_deterministic_seed(self):
        a = core.encrypt_source('x = 1', seed='fixed')
        b = core.encrypt_source('x = 1', seed='fixed')
        self.assertEqual(a[1]['key'], b[1]['key'])
        self.assertNotEqual(a[0], core.encrypt_source('x = 1')[0])

    def test_rejects_bad_input(self):
        with self.assertRaises(ShlhomError):
            core.encrypt_source(b'not a string')
        with self.assertRaises(ShlhomError):
            core.encrypt_source('x = 1\x00')

    def test_strict_raises(self):
        with self.assertRaises(ShlhomError):
            core.encrypt_source('def (', strict=True)

    def test_no_obfuscate(self):
        stage, meta = core.encrypt_source('SECRET = 1', obfuscate=False)
        compile(stage, '<t>', 'exec')


class TestBuildPayload(unittest.TestCase):
    def test_verify_launcher(self):
        stage, _ = core.encrypt_source('print(1)')
        launcher = core.pack_payload(stage, size_kb=1, native=False)
        self.assertTrue(core.verify_launcher(launcher))

    def test_detects_tamper(self):
        stage, _ = core.encrypt_source('print(1)')
        launcher = core.pack_payload(stage, size_kb=1, native=False)
        idx = launcher.index('_B64 = "') + len('_B64 = "')
        broken = launcher[:idx] + ('A' if launcher[idx] != 'A' else 'B') + launcher[idx + 1:]
        with self.assertRaises(ShlhomError):
            core.verify_launcher(broken)

    def test_container_contents(self):
        stage, _ = core.encrypt_source('print(1)')
        launcher = core.pack_payload(stage, size_kb=1, native=False)
        start = launcher.index('_B64 = "') + len('_B64 = "')
        raw = core.base64.b64decode(launcher[start:launcher.index('"', start)])
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = set(zf.namelist())
            self.assertEqual(names, {'__main__.py', 'payload.sha256', 'payload.shlbin'})
            blob = zf.read('payload.shlbin')
            want = zf.read('payload.sha256').decode().strip()
            self.assertEqual(hashlib.sha256(blob).hexdigest(), want)

    def test_no_native_uses_marshal(self):
        stage, _ = core.encrypt_source('print(1)')
        launcher = core.pack_payload(stage, size_kb=1, native=False)
        start = launcher.index('_B64 = "') + len('_B64 = "')
        raw = core.base64.b64decode(launcher[start:launcher.index('"', start)])
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            blob = zf.read('payload.shlbin')
        self.assertNotEqual(blob[:4], b'\x7fELF')
        code = core.marshal.loads(blob)
        self.assertEqual(code.co_filename, '<shlhom_azr_payload>')

    def test_pad(self):
        stage, _ = core.encrypt_source('print(1)')
        launcher = core.pack_payload(stage, size_kb=4, pad=True, native=False)
        start = launcher.index('_B64 = "') + len('_B64 = "')
        raw = core.base64.b64decode(launcher[start:launcher.index('"', start)])
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            blob = zf.read('payload.shlbin')
        self.assertGreaterEqual(len(blob), 4096)


class TestElfBuilder(unittest.TestCase):
    def test_marshal_fallback(self):
        work = tempfile.mkdtemp(prefix='shlhom_test_')
        try:
            out = Path(work) / 'payload.bin'
            mode = shll_build('print(1)', out, 0, native=False)
            self.assertEqual(mode, 'marshal')
            self.assertTrue(out.exists())
            self.assertEqual(core.marshal.loads(out.read_bytes()).co_names, ('print',))
        finally:
            shutil.rmtree(work, ignore_errors=True)


class TestTshfer(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix='shlhom_test_')

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _write(self, name, body):
        path = Path(self.work) / name
        path.write_text(textwrap.dedent(body), encoding='utf-8')
        return path

    def test_default_output_name(self):
        src = self._write('tool.py', '''
            class Greeter:
                def __init__(self, name):
                    self.name = name
                def hello(self):
                    return 'hi ' + self.name
            if __name__ == '__main__':
                print(Greeter('azr').hello())
        ''')
        out = tshfer(src, size_kb=1, native=False)
        self.assertTrue(out.endswith('_shlhom_azr.py'))
        self.assertTrue(Path(out).exists())
        text = Path(out).read_text(encoding='utf-8')
        self.assertNotIn('Greeter', text)
        self.assertNotIn('hi ', text)
        result = _run_module(out)
        self.assertIn('hi azr', result.stdout)
        self.assertIn('hi azr', result.stderr + result.stdout)

    def test_output_keyword(self):
        src = self._write('tool.py', 'print("kw")')
        out = tshfer(src, output=str(Path(self.work) / 'named.py'),
                     size_kb=1, native=False)
        self.assertTrue(out.endswith('named.py'))

    def test_size_keyword(self):
        src = self._write('tool.py', 'print(1)')
        out = tshfer(src, size_kb=7, native=False, pad=True)
        start = Path(out).read_text(encoding='utf-8').index('_B64 = "') + 8
        text = Path(out).read_text(encoding='utf-8')
        raw = core.base64.b64decode(text[start:text.index('"', start)])
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            self.assertGreaterEqual(len(zf.read('payload.shlbin')), 7 * 1024)

    def test_missing_file(self):
        with self.assertRaises(ShlhomError):
            tshfer(str(Path(self.work) / 'nope.py'))

    def test_protect_alias(self):
        self.assertIs(protect, tshfer)

    def test_carries_azr_branding(self):
        src = self._write('tool.py', 'print(1)')
        out = Path(tshfer(src, size_kb=1, native=False))
        text = out.read_text(encoding='utf-8')
        self.assertIn('@AZR_hk', text)
        self.assertNotIn('t' + '.me/', text)
        self.assertIn('[lshlhom/AZR]', text)
        head, sep, rest = text.partition('_B64 = "')
        self.assertTrue(sep)
        self.assertNotIn('1 0 obj', head)
        self.assertNotIn('uesdb', head)


def _run_module(path):
    import subprocess
    return subprocess.run(
        [sys.executable, str(path)],
        capture_output=True, text=True, timeout=120,
        cwd=str(Path(path).parent),
    )


class TestMetadata(unittest.TestCase):
    def test_version(self):
        self.assertEqual(__version__, '1.1.0')

    def test_setup_matches(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import re
        text = (Path(__file__).resolve().parent.parent / 'lshlhom' / '__init__.py').read_text(encoding='utf-8')
        version = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)", text, re.M).group(1)
        self.assertEqual(version, __version__)

    def test_credits_present(self):
        import lshlhom
        credits = ' '.join(lshlhom.__credits__)
        self.assertIn('shlhom', credits)
        self.assertIn('AZR', credits)
        self.assertIn('@AZR_hk', credits)

    def test_no_telegram_links(self):
        root = Path(__file__).resolve().parent.parent
        targets = ['README.md', 'setup.py', 'pyproject.toml', 'CHANGELOG.md',
                   'LICENSE', 'MANIFEST.in', 'setup.cfg', 'PKG-INFO',
                   'lshlhom.egg-info/PKG-INFO']
        targets += [str(p.relative_to(root)) for p in (root / 'lshlhom').glob('*.py')]
        targets += ['tests/test_lshlhom.py']
        for rel in targets:
            path = root / rel
            if not path.exists():
                continue
            for lineno, line in enumerate(
                path.read_text(encoding='utf-8').splitlines(), 1
            ):
                if 'assertNotIn' in line or 'assert_' in line:
                    continue
                low = line.lower()
                for marker in ('t' + '.me/', 'telegram' + '.me/', 'tg' + '://'):
                    self.assertNotIn(
                        marker, low,
                        f'{rel}:{lineno} contains a telegram link: {line.strip()!r}',
                    )

    def test_no_comment_markers_in_source(self):
        root = Path(__file__).resolve().parent.parent / 'lshlhom'
        for path in sorted(root.glob('*.py')):
            text = path.read_text(encoding='utf-8')
            stripped = text.lstrip()
            self.assertFalse(stripped.startswith('#'), f'{path.name} starts with a comment')
            for line in text.splitlines():
                code = line
                if "'" in code or '"' in code:
                    continue
                self.assertFalse(code.strip().startswith('#'),
                                 f'{path.name} has a comment line: {line!r}')


class TestCLI(unittest.TestCase):
    def test_parser(self):
        from lshlhom.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(['a.py', '-s', '10', '--no-native'])
        self.assertEqual(args.files, ['a.py'])
        self.assertEqual(args.size_kb, 10)
        self.assertTrue(args.no_native)

    def test_version_flag(self):
        from lshlhom.cli import build_parser
        with self.assertRaises(SystemExit):
            build_parser().parse_args(['--version'])

    def test_check_does_not_require_positional(self):
        from lshlhom.cli import build_parser
        args = build_parser().parse_args(['--check', 'some.py'])
        self.assertEqual(args.check, 'some.py')
        self.assertEqual(args.files, [])

    def test_no_files_errors(self):
        from lshlhom.cli import main
        with self.assertRaises(SystemExit):
            main([])

    def test_check_missing_file_fails(self):
        from lshlhom.cli import main
        self.assertEqual(main(['--check', 'definitely_missing.py']), 1)

    def test_check_ok(self):
        from lshlhom.cli import main
        work = tempfile.mkdtemp(prefix='shlhom_test_')
        try:
            src = Path(work) / 'ok.py'
            src.write_text('print(1)', encoding='utf-8')
            out = Path(tshfer(src, size_kb=1, native=False))
            self.assertEqual(main(['--check', str(out)]), 0)
        finally:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)

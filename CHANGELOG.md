# Changelog

## 1.1.0

Co-developed by AZR (@AZR_hk) on top of the original
library by shlhom (@yy22ff). Original rights stay with shlhom.

### Fixed

- Class methods, class attributes and dataclass fields are no longer renamed
  while attribute access keeps the original name. Protected files that used
  classes, `getattr`, `super().__init__` or dataclasses raised
  `AttributeError` or `TypeError` at runtime before this release.
- Names bound by `import`, `from x import y`, `except ... as e` and class body
  assignments are never renamed.
- Builtins, dunder names and safe helper names are never renamed.
- String literals inside `match` patterns stay literals, so `match` statements
  parse and run after protection.
- The generated file no longer dies silently: failures print a readable
  `[lshlhom/AZR]` message and return a non zero exit code.
- The embedded payload is verified with SHA-256 before it runs, so an edited
  protected file is rejected instead of crashing.
- `__file__`, `sys.argv[0]` and `__name__` now point at the protected `.py`
  file, and the exit code of the program is passed through unchanged.
- The build no longer uses `os.system` with string paths, uses private
  temporary directories, and never collides between parallel runs.
- Compiler and Cython steps check their exit status before using the output.
- `tshfer` accepts the documented `output=` and `size_kb=` keyword arguments.
- `lshlhom --check` no longer demands a positional file, and running the
  command without arguments now prints a clear error instead of a usage dump
  that hid the real problem.
- The output is written atomically, so an interrupted build leaves no partial
  file behind.

### Added

- `lshlhom` command line tool and `python -m lshlhom`.
- `ShlhomError` for every failure raised by the library.
- `strict` mode: ast failures now raise instead of silently shipping an
  unprotected file. `--no-strict` restores the old behaviour.
- `native=False` to skip the native binary step for a much faster build.
- `pad=False`, `obfuscate=False`, `rename_defs`, `seed` and `verify` options.
- Every protected build is verified layer by layer before it is written.
- `LICENSE`, `CHANGELOG.md`, `pyproject.toml` and a dependency free
  `unittest` suite.
- `python_requires` corrected to `>=3.9`, which is what the library actually
  needs for `ast.unparse` and `random.randbytes`.

### Changed

- Generated files carry the AZR mark and use AZR temp names, while the package
  name `lshlhom` and the import path stay the same.
- Default generated suffix is `_shlhom_azr.py`.
- Requires Python 3.9 or newer.

## 1.0.0

First release by shlhom.

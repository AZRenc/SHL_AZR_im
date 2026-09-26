import os
import sys
import argparse

from .core import ShlhomError, tshfer, verify_launcher, AZR_TAG
from . import __version__


def build_parser():
    parser = argparse.ArgumentParser(
        prog='lshlhom',
        description='Protect a Python file with layered encryption. '
                    'Original library by shlhom (@yy22ff), '
                    '1.1.0 line co-developed by AZR (@AZR_hk).',
    )
    parser.add_argument('files', nargs='*', help='python file(s) to protect')
    parser.add_argument('-o', '--output', help='output path, only with one file')
    parser.add_argument('-s', '--size-kb', type=int, default=800,
                        help='output size floor in kilobytes, default 800')
    parser.add_argument('--no-pad', action='store_true',
                        help='do not pad the payload up to size-kb')
    parser.add_argument('--no-native', action='store_true',
                        help='skip the native binary step, faster but smaller layer count')
    parser.add_argument('--no-obfuscate', action='store_true',
                        help='keep the source readable, only encrypt it')
    parser.add_argument('--rename-defs', action='store_true',
                        help='also rename function names, can break attribute access')
    parser.add_argument('--no-strict', action='store_true',
                        help='skip ast obfuscation instead of failing')
    parser.add_argument('--seed', help='deterministic build key, weakens protection')
    parser.add_argument('--suffix', default='_shlhom_azr.py',
                        help='suffix for the generated file name')
    parser.add_argument('--check', metavar='FILE',
                        help='verify a protected file and exit')
    parser.add_argument('-v', '--verbose', action='store_true', help='print progress')
    parser.add_argument('-V', '--version', action='version',
                        version=f'lshlhom {__version__}')
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.check:
        try:
            with open(args.check, 'r', encoding='utf-8', errors='ignore') as fh:
                verify_launcher(fh.read())
        except (OSError, ShlhomError) as exc:
            sys.stderr.write(f'[lshlhom/AZR] {exc}\n')
            return 1
        sys.stdout.write(f'[lshlhom/AZR] {args.check} is intact\n')
        return 0

    if args.output and len(args.files) > 1:
        parser.error('--output works with a single file only')
    if not args.files:
        parser.error('at least one python file is required')

    failed = 0
    for item in args.files:
        try:
            out = tshfer(
                item,
                output=args.output,
                size_kb=args.size_kb,
                pad=not args.no_pad,
                native=not args.no_native,
                obfuscate=not args.no_obfuscate,
                rename_defs=args.rename_defs,
                strict=not args.no_strict,
                seed=args.seed,
                verbose=args.verbose,
                suffix=args.suffix,
            )
        except (ShlhomError, OSError) as exc:
            sys.stderr.write(f'[lshlhom/AZR] {item}: {exc}\n')
            failed += 1
            continue
        if not args.verbose:
            sys.stdout.write(f'{out}\n')
    if failed:
        sys.stderr.write(f'[lshlhom/AZR] {failed} file(s) failed\n')
        return 1
    if args.verbose:
        sys.stderr.write(f'[lshlhom/AZR] {AZR_TAG}\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())

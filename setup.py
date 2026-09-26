import os
import re

from setuptools import setup, find_packages

HERE = os.path.abspath(os.path.dirname(__file__))


def read(name):
    with open(os.path.join(HERE, name), 'r', encoding='utf-8') as fh:
        return fh.read()


def meta(name):
    text = read(os.path.join('lshlhom', '__init__.py'))
    found = re.search(rf"^__{name}__\s*=\s*['\"]([^'\"]+)['\"]", text, re.M)
    if not found:
        raise RuntimeError(f'cannot find __{name}__ in lshlhom/__init__.py')
    return found.group(1)


setup(
    name='lshlhom',
    version=meta('version'),
    author=meta('author'),
    author_email=meta('author_email'),
    maintainer=meta('developer'),
    description='Protect Python files with layered encryption',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    license='MIT',
    license_files=['LICENSE'],
    packages=find_packages(include=['lshlhom', 'lshlhom.*']),
    include_package_data=True,
    zip_safe=False,
    entry_points={'console_scripts': ['lshlhom = lshlhom.cli:main']},
    python_requires='>=3.9',
    install_requires=[],
    extras_require={'native': ['Cython>=3.0']},
    keywords='protect obfuscate encrypt marshal sm4 base91 huffman azr shlhom',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Natural Language :: Arabic',
        'Natural Language :: English',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Build Tools',
    ],
)

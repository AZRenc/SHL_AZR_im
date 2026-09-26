from .core import tshfer
from .core import protect
from .core import ShlhomError
from .core import encrypt_source
from .core import pack_payload
from .core import verify_launcher
from .core import AZR_USER
from .core import AZR_TAG

__version__ = '1.1.0'

__title__ = 'lshlhom'
__summary__ = 'Protect Python files with layered encryption'
__license__ = 'MIT'

__author__ = 'shlhom'
__author_email__ = 'adojod1231@gmail.com'
__author_telegram__ = '@yy22ff'

__developer__ = 'AZR'
__developer_telegram__ = '@AZR_hk'

__original_copyright__ = 'Copyright (c) shlhom'
__developer_copyright__ = 'Copyright (c) AZR (contributions to 1.1.0 and newer)'

__credits__ = (
    'Original library and original rights: shlhom (@yy22ff)',
    'Co-developer of the 1.1.0 line: AZR (@AZR_hk)',
)

__all__ = [
    'tshfer', 'protect', 'ShlhomError', 'encrypt_source', 'pack_payload',
    'verify_launcher', 'AZR_USER', 'AZR_TAG', '__version__',
    '__credits__',
]

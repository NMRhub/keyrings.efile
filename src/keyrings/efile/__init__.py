__version__ = 4.1

# allow keyrings.efile.cli, installed by the keyrings.efile.cli distribution, to live in a separate directory
from pkgutil import extend_path
__path__ = extend_path(__path__, __name__)

import logging
kef_logger = logging.getLogger("keyrings.efile")

from keyrings.efile.encryptedfile import EncryptedFile
from keyrings.efile.handler import FallbackPasswordHandler

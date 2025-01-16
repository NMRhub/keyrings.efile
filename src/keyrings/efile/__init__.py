__version__ = 3.0

import logging
kef_logger = logging.getLogger("keyrings.efile")

from keyrings.efile.encryptedfile import EncryptedFile
from keyrings.efile.handler import FallbackPasswordHandler

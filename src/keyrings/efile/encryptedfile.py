import binascii
import configparser
import hashlib
import os
import random
import secrets
import string
import sys
from collections import defaultdict
from typing import Optional, NamedTuple, Dict, List, Tuple

import filelock
from Crypto.Cipher import AES
from jaraco.classes import properties
from keyring import errors
from keyring.backend import KeyringBackend

from keyrings.efile import kef_logger

"""cache authentication in local file specified from config file.
The password is entered manually from command line first time code is run. Subsequent
runs will decrypt previously entered password.

The expected configuration file entry is

[Password Cache]
local file = path to file name
key file = path binary key file

both files are generated automatically if they don't exist.
"""
assert sys.version_info >= (3, 6)


class LockedConfig:
    """Configparser wrapper which locks file"""

    def __init__(self,filename):
        self.filename = filename
        self.lock = filelock.FileLock(f"{filename}.lock")

    def __enter__(self):
        cfg = configparser.ConfigParser()
        self.lock.acquire()
        if os.path.isfile(self.filename):
            with open(self.filename) as f:
                cfg.read_file(f)
        return cfg

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lock.release()


_CACHE_KEY = 'Password Cache'
_FILE_OPT = 'local file'
_KEY_OPT = 'key file'
_DMI_FILE = '/sys/firmware/dmi/entries/1-0/raw'
# prefix of values encrypted with key combined with DMI system information
_V2_PREFIX = 'v2:'


def _machine_id() -> Optional[bytes]:
    """return DMI system information (type 1) if running as root and available"""
    if os.geteuid() != 0:
        return None
    try:
        with open(_DMI_FILE, 'rb') as f:
            return f.read()
    except OSError:
        kef_logger.warning(f"Unable to read {_DMI_FILE}")
        return None


def _random_in_range(low: int, high: int):
    """return random number in specified range"""
    # check version to use most appropriate random function
    return secrets.randbelow(high - low) + low


class PasswordStatus(NamedTuple):
    password : str
    cipher : str


class PasswordSalted:
    _IV_STR = '29 e0 9b 8f 98 3a fa 16 ca ef 8f 24 e8 54 e3 6c'
    __PADDED_LENGTH = 256
    __DIGIT_SIZE = 3
    _pool = None

    def __init__(self, key_file: str, machine_id: Optional[bytes] = None):
        """key_file binary key file
        machine_id if given, combined with key file contents to bind encryption to hardware"""
        with open(key_file, "br") as fhandle:
            self.cipher_key = fhandle.read()
        if machine_id is not None:
            self.cipher_key = hashlib.sha256(self.cipher_key + machine_id).digest()
        self.initialization_vector = bytes.fromhex(self._IV_STR)

    @staticmethod
    def pool() -> tuple:
        """lazy getter for pool to get random characters from"""
        if not PasswordSalted._pool:
            ltr = {x for x in string.ascii_letters}
            dg = {x for x in string.digits}
            punct = {x for x in string.punctuation}
            PasswordSalted._pool = tuple(ltr.union(dg, punct))
        return PasswordSalted._pool

    def randletters(self, number: int) -> str:
        """Get number of random letters from self.pool()"""
        c = []
        for _ in range(0, number):
            c.append(random.choice(self.pool()))
        return ''.join(c)

    def encrypt(self, pword: str) -> str:
        """encrypt pword using key passed at construction
        :type pword: str
        """
        cipher = AES.new(
            self.cipher_key, AES.MODE_CFB, self.initialization_vector)
        assert isinstance(cipher, object)
        pw_length = len(pword)
        padding = self.__PADDED_LENGTH - len(pword) - 2 * self.__DIGIT_SIZE
        insert_location = _random_in_range(0, padding)
        pre = self.randletters(insert_location)
        postbytes = self.randletters(padding - insert_location)
        padded_str = "{:0{len}d}{}{:0{len}d}{}{}".format(insert_location, pre, pw_length, pword, postbytes,
                                                         len=self.__DIGIT_SIZE)
        return cipher.encrypt(padded_str.encode())

    def decrypt(self, cipher_text: bytes) -> str:
        """encrypt pword using key passed at construction
        """
        cipher = AES.new(
            self.cipher_key, AES.MODE_CFB, self.initialization_vector)
        bstr = cipher.decrypt(cipher_text)
        decoded = bstr.decode()
        istr = decoded[0:self.__DIGIT_SIZE]
        offset = int(istr) + self.__DIGIT_SIZE
        active = decoded[offset:]
        length_str = active[0:self.__DIGIT_SIZE]
        pword_length = int(length_str)
        pword = active[self.__DIGIT_SIZE:self.__DIGIT_SIZE + pword_length]
        return pword



    def get_password(self, service: str, username: str) -> Optional[str]:
        pass

    def set_password(self, service: str, username: str, password: str) -> None:
        pass

class EncryptedFile(KeyringBackend) :

    def __init__(self):
        self.__name__ = 'keyrings.efile'
        super().__init__()
        uid = str(os.getuid())
        basedir = '/var/tmp/.efilepassword'
        os.makedirs(basedir,mode=0o777,exist_ok=True)
        self.data_file = os.path.join(basedir,f"data{uid}")
        key_file = os.path.join(basedir,f"key{uid}")
        lock = filelock.FileLock(f"{key_file}.lock")
        with lock:
            if not os.path.exists(key_file):
                self._gen_key(key_file)
        self.legacy_pw_obj = PasswordSalted(key_file)
        machine_id = _machine_id()
        self.machine_pw_obj = PasswordSalted(key_file, machine_id) if machine_id is not None else None
        # status is an in memory cache to avoid going back to disk if password already known
        self.status : Dict[str,Dict[str, PasswordStatus]]= defaultdict(dict)  # [str][str] = PasswordStatus


    @property
    def name(self) -> str:
        return  'keyrings.efile'

    @properties.classproperty
    def priority(cls) -> int:
        return 20



    @staticmethod
    def _gen_key(key_file: str):
        dirname = os.path.dirname(key_file)
        os.makedirs(dirname,0o700,exist_ok=True)
        with open('/dev/random', 'rb') as rin:
            with open(key_file, 'xb') as rout:
                for i in range(0, 32):
                    abyte = rin.read(1)
                    rout.write(abyte)
        os.chmod(key_file, mode=0o400)

    def get_password(self, service: str, user: str) -> Optional[str]:
        """Return password for user if already set for context; otherwise prompt for and store password
        @param user: account name password corresponds to
        @param service: application using password 
        @param test_password: set specified password (implemented for testing)
        @return existing password or value from keyboard
        """
        try:
            return self.status[user][service].password
        except KeyError:
            kef_logger.debug(f"{service} {user} not in memory cache, looking up from file, reading {self.data_file}")
        with LockedConfig(self.data_file) as password_config:
            cc = password_config
            if not cc.has_section(user):
                cc.add_section(user)
            user_config = cc[user]
            hex_cipher = user_config.get(service)
            if hex_cipher is None:
                return None
            if hex_cipher.startswith(_V2_PREFIX):
                if self.machine_pw_obj is None:
                    raise errors.KeyringError(f"{service} {user} requires root access to {_DMI_FILE} to decrypt")
                decrypted = self.machine_pw_obj.decrypt(binascii.unhexlify(hex_cipher[len(_V2_PREFIX):]))
                self.status[user][service] = PasswordStatus(decrypted, hex_cipher)
                return decrypted
            try:
                cipher_bytes = binascii.unhexlify(hex_cipher)
            except binascii.Error:
                kef_logger.error(f"Invalid stored cipher for {service} {user} in {self.data_file}: "
                                 f"length={len(hex_cipher)} value={hex_cipher[:8]!r}...")
                raise
            decrypted = self.legacy_pw_obj.decrypt(cipher_bytes)
            if self.machine_pw_obj is not None:
                kef_logger.debug(f"Rewriting {service} {user} in machine bound format")
                c_str = self._encode(decrypted)
                user_config[service] = c_str
                self._write(cc)
            else:
                c_str = hex_cipher
            self.status[user][service] = PasswordStatus(decrypted, c_str)
            return decrypted

    def _encode(self, pw: str) -> str:
        """encrypt password and hex encode, using machine bound format if available"""
        if self.machine_pw_obj is not None:
            return _V2_PREFIX + binascii.hexlify(self.machine_pw_obj.encrypt(pw)).decode()
        return binascii.hexlify(self.legacy_pw_obj.encrypt(pw)).decode()

    def _write(self, lockedconfig: configparser.ConfigParser) -> None:
        """write config to data file; caller must hold lock"""
        # write to a temp file and rename so readers never see a truncated file
        tmp_file = f"{self.data_file}.tmp{os.getpid()}"
        fd = os.open(tmp_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode=0o600)
        try:
            with os.fdopen(fd, 'w') as configfile:
                lockedconfig.write(configfile)
                configfile.flush()
                os.fsync(configfile.fileno())
            os.replace(tmp_file, self.data_file)
        except BaseException:
            if os.path.exists(tmp_file):
                os.unlink(tmp_file)
            raise
        kef_logger.debug(f"Wrote {self.data_file}")

    def set_password(self, service: str, user: str, pw: str) -> None:
        c_str = self._encode(pw)
        with LockedConfig(self.data_file) as lockedconfig:
            if not lockedconfig.has_section(user):
                lockedconfig.add_section(user)
            user_config = lockedconfig[user]
            user_config[service] = c_str
            self.status[user][service] = PasswordStatus(pw, c_str)
            self._write(lockedconfig)

    def list_entries(self) -> List[Tuple[str, str]]:
        """Return sorted (service, user) pairs stored in the data file"""
        with LockedConfig(self.data_file) as password_config:
            return sorted((service, user)
                          for user in password_config.sections()
                          for service in password_config.options(user))

    def delete_password(self, service: str, user: str) -> None:
        try:
            if self.get_password(service,user) is not None:
                with LockedConfig(self.data_file) as lockedconfig:
                    lockedconfig.remove_option(user,service)
                    self._write(lockedconfig)
                self.status[user].pop(service, None)
            else:
                kef_logger.debug(f"No password for {service} {user}")
        except Exception as e:
            kef_logger.exception(f"delete {service} {user}")
            raise errors.PasswordDeleteError(str(e))


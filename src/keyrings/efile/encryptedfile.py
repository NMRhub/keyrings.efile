import binascii
import configparser
import os
import random
import secrets
import string
import sys
from collections import defaultdict
from typing import Optional, NamedTuple, Dict

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

    def __init__(self, key_file: str):
        """cparser ConfigParser instance"""
        with open(key_file, "br") as fhandle:
            self.cipher_key = fhandle.read()
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
        self.pw_obj = PasswordSalted(key_file)
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
            if hex_cipher is not None:
                pw_cipher = binascii.unhexlify(hex_cipher)
                decrypted = self.pw_obj.decrypt(pw_cipher)
                self.status[user][service] = PasswordStatus(decrypted, hex_cipher)
                return decrypted
        return None

    def set_password(self, service: str, user: str, pw: str) -> None:
        ciphered = self.pw_obj.encrypt(pw)
        c_str = binascii.hexlify(ciphered).decode()
        self.status[user][service] = PasswordStatus(pw, c_str)
        with LockedConfig(self.data_file) as lockedconfig:
            if not lockedconfig.has_section(user):
                lockedconfig.add_section(user)
            user_config = lockedconfig[user]
            user_config[service] = c_str
            self.status[user][service] = PasswordStatus(pw, c_str)
            fd = os.open(self.data_file, os.O_CREAT, mode=0o600)
            os.close(fd)
            with open(self.data_file, 'w+') as configfile:
                lockedconfig.write(configfile)
            kef_logger.debug(f"Wrote {self.data_file} for set")

    def delete_password(self, service: str, user: str) -> None:
        try:
            if self.get_password(service,user) is not None:
                with LockedConfig(self.data_file) as lockedconfig:
                    lockedconfig.remove_option(user,service)
                    fd = os.open(self.data_file, os.O_CREAT, mode=0o600)
                    os.close(fd)
                    with open(self.data_file, 'w+') as configfile:
                        lockedconfig.write(configfile)
                    kef_logger.debug(f"Wrote {self.data_file} for delete")
            else:
                kef_logger.debug(f"No password for {service} {user}")
        except Exception as e:
            kef_logger.exception(f"delete {service} {user}")
            raise errors.PasswordDeleteError(str(e))


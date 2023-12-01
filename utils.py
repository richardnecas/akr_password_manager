from enum import Enum


class Algorithm(Enum):
    AES = 0
    Camelia = 1
    Fernet = 2


class KeyLength(Enum):
    bit128 = 0
    bit194 = 1
    bit256 = 2


class FilePath(Enum):
    private = 'private.pem'
    public = 'public.pem'
    metadata = 'metadata.dat'
    log = 'log.dat'

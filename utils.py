from enum import Enum


class FilePath(Enum):
    private = 'private.pem'
    public = 'public.pem'
    metadata = 'metadata.dat'
    log = 'log.dat'
    database = 'database.dat'

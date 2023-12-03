from enum import Enum


class FilePath(Enum):
    private = '../pmfiles/private.pem'
    public = '../pmfiles/public.pem'
    metadata = '../pmfiles/metadata.dat'
    log = '../pmfiles/log.dat'
    database = '../pmfiles/database.dat'

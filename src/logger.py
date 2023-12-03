from utils import FilePath
import time
import datetime
from enum import Enum


class LogMessage(Enum):
    password_create = 'Password created'
    password_delete = 'Password deleted'
    password_change = 'Password changed'
    app_started = '\nApplication started'
    successful_login = 'Log-in successful'
    failed_login = 'Failed log-in attempt'
    authentication_try = 'Sending authentication request'
    authentication_successful = 'User successfully authenticated'
    authentication_failed = 'User authentication failed'
    decryption_finish = 'Decryption finished'
    encryption_start = 'Encryption started'
    database_save = 'Database saved'
    app_close = 'Application closed'


def make_log(message):
    with open(FilePath.log.value, 'a') as to_log:
        to_log.write(message + " | " + str(datetime.datetime.fromtimestamp(time.time()).strftime('%H:%M:%S')) + "\n")
    print(message)

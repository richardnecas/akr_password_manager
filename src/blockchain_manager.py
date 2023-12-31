import json
import integrity_manager
import password
from typing import List
import file_manager
from utils import FilePath
from logger import LogMessage, make_log

passwords: List[password.Password] = []


def get_database():
    return passwords


def add_password(password_params: password.PasswordBlueprint):
    if len(passwords) == 0:
        new_password = password.Password(password_params.url, password_params.password, "")
        passwords.append(new_password)
    else:
        new_password = password.Password(password_params.url, password_params.password, passwords[-1].hash)
        passwords.append(new_password)
    make_log(LogMessage.password_create.value)


def delete_password(index):
    passwords.pop(index)
    if len(passwords) > 0:
        recount_blockchain_from_index(index)
    make_log(LogMessage.password_delete.value)


def change_password(password_params, index):
    update_password_params(password_params, index)
    recount_blockchain_from_index(index)
    make_log(LogMessage.password_change.value)


def recount_blockchain_from_index(index):
    global passwords

    if index == 0:
        passwords[0].previous_hash = ""
        passwords[0].hash = passwords[0].calculate_hash()
        previous_index = 0
        for i in range(1, len(passwords)):
            passwords[i].previous_hash = passwords[previous_index].hash
            passwords[i].hash = passwords[i].calculate_hash()
            previous_index += 1
    else:
        previous_index = index - 1
        for i in range(index, len(passwords)):
            passwords[i].previous_hash = passwords[previous_index].hash
            passwords[i].hash = passwords[i].calculate_hash()
            previous_index += 1


def update_password_params(password_params: password.PasswordBlueprint, index):
    global passwords

    new_password = password.Password(password_params.url, password_params.password, passwords[index - 1].hash)
    passwords[index] = new_password


def database_encode():  # encodes database into dictionary array
    dictionary_list = []
    for dat in passwords:
        cache_password = {
            "url": dat.url,
            "password": dat.password,
            "previous_hash": dat.previous_hash,
            "hash": dat.hash,
            "timestamp": dat.timestamp
        }
        dictionary_list.append(cache_password)
    return json.dumps(dictionary_list).encode('utf-8')


def database_decode(dictionary_list: [{}]):  # decodes the loaded array into array of objects and assigns it to passwords array
    cache_passwords: List[password.Password] = []
    for dat in dictionary_list:
        cache_password = password.Password("", "", "")
        cache_password.hash = dat["hash"]
        cache_password.previous_hash = dat["previous_hash"]
        cache_password.url = dat["url"]
        cache_password.password = dat["password"]
        cache_password.timestamp = dat["timestamp"]
        cache_passwords.append(cache_password)
    return cache_passwords


def save_database_to_file():
    file_manager.write_file(integrity_manager.encrypt_database(database_encode()), FilePath.database.value)
    make_log(LogMessage.database_save.value)


def load_database_from_file(master_password):  # tries to load and decrypt the database
    global passwords
    try:
        passwords = database_decode(json.loads(
            integrity_manager.decrypt_database(file_manager.open_file(FilePath.database.value), master_password).decode('utf-8')))
        make_log(LogMessage.decryption_finish.value)
    except Exception:
        return False
    return integrity_manager.run_integrity_check(database_encode(), passwords)

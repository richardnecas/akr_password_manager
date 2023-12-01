import json

import integrity_manager
import password
from typing import List
import file_manager
from utils import Algorithm

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


def delete_password(index):
    passwords.pop(index)
    if len(passwords) > 0:
        recount_blockchain_from_index(index)


def change_password(password_params, index):
    update_password_params(password_params, index)
    recount_blockchain_from_index(index)


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

    new_password = password.Password(password_params.url, password_params.password, passwords[index-1].hash)
    passwords[index] = new_password


def database_encode():
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


def database_decode(dictionary_list: [{}]):
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
    file_manager.write_file(integrity_manager.encrypt_database(database_encode()), 'database.dat')


def load_database_from_file(master_password):
    global passwords
    passwords = database_decode(json.loads(integrity_manager.decrypt_database(file_manager.open_file('database.dat'), master_password).decode('utf-8')))
    return integrity_manager.run_integrity_check(database_encode(), passwords)


'''integrity_manager.generate_next_session_key('silneheslo')
pass1 = password.Password("web.cz", "password", "")
passwords.append(pass1)
pass2 = password.Password("stranka.org", "heslo", passwords[0].hash)
passwords.append(pass2)
pass3 = password.PasswordBlueprint("google.cz", "nevimuz")
add_password(pass3)
pass4 = password.PasswordBlueprint("nope", "nenavidimpython")
add_password(pass4)
pass5 = password.PasswordBlueprint("hehe", "radzadavamtypypromennych")
add_password(pass5)
integrity_manager.set_mode(0)
integrity_manager.set_key_length(32)
save_database_to_file()
print(load_database_from_file('silneheslo'))'''

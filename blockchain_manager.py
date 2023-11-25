import json

import integrity_manager
import password
from typing import List
import file_manager
from utils import Algorithm

passwords: List[password.Password] = []


def add_password(password_params: password.PasswordBlueprint):
    if len(passwords) == 0:
        new_password = password.Password(password_params.url, password_params.password, "")
        passwords.append(new_password)
    else:
        new_password = password.Password(password_params.url, password_params.password, passwords[-1].hash)
        passwords.append(new_password)


def delete_password(index):
    recount_blockchain_from_index(passwords.pop(index))


def change_password(password_params, index):
    update_password_params(password_params, index)
    recount_blockchain_from_index(index)


def recount_blockchain_from_index(index):
    global passwords

    if index == 0:
        passwords[0].previous_hash = ""
        passwords[0].hash = passwords[0].calculate_hash()
        previous_index = 0
        for i in range(len(passwords[2:])):
            passwords[i].previous_hash = passwords[previous_index].hash
            passwords[i].hash = passwords[i].calculate_hash()
            previous_index += 1
    else:
        previous_index = index - 1
        for i in range(len(passwords[index:])):
            passwords[i].previous_hash = passwords[previous_index].hash
            passwords[i].hash = passwords[i].calculate_hash()
            previous_index += 1


def update_password_params(password_params: password.PasswordBlueprint, index):
    global passwords

    if password_params.url == "":
        cache_url = passwords[index].url
    else:
        cache_url = password_params.url

    cache_password = password.Password(cache_url, password_params.password, passwords[index].hash)
    passwords[index] = cache_password


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


def database_decode(dictionary_list: [{}], master_password):
    cache_passwords: List[password.Password] = []
    for dat in dictionary_list:
        cache_password = password.Password(dat["url"], dat["password"], dat["previous_hash"])
        cache_passwords.append(cache_password)
    return cache_passwords


def save_database_to_file(algorithm_mode, key_length, master_password):
    file_manager.write_file(integrity_manager.encrypt_database(database_encode(), algorithm_mode, key_length, master_password), 'database.dat')


def load_database_from_file(master_password):
    global passwords
    passwords = database_decode(json.loads(integrity_manager.decrypt_database(file_manager.open_file('database.dat'), master_password).decode('utf-8')), master_password)


pass1 = password.Password("web.cz", "password", "")
pass2 = password.Password("stranka.org", "heslo", pass1.hash)
passwords.append(pass1)
passwords.append(pass2)
save_database_to_file(0, 32, "silneheslo")
load_database_from_file('silneheslo')
print(database_encode())

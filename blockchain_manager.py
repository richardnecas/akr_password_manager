import integrity_manager
import password
from typing import List
import file_manager
from utils import AlgorithmModes

passwords: List[password.Password] = []


def add_password(password_params: password.PasswordBlueprint, master_password):
    if len(passwords) == 0:
        new_password = password.Password(password_params.url, password_params.password, "", master_password)
        passwords.append(new_password)
    else:
        new_password = password.Password(password_params.url, password_params.password, passwords[-1].hash, master_password)
        passwords.append(new_password)


def delete_password(index):
    deleted = passwords.pop(index)
    recount_blockchain_from_index(deleted)


def change_password(password_params, master_password, index):
    update_password_params(password_params, master_password, index)
    recount_blockchain_from_index(index)


def recount_blockchain_from_index(index):
    global passwords

    if index == 0:
        passwords[0].previous_hash = ""
        passwords[0].calculate_hash()
        previous_index = 0
        for i in range(len(passwords[2:])):
            passwords[i].previous_hash = passwords[previous_index].hash
            passwords[i].calculate_hash()
            previous_index += 1
    else:
        previous_index = index - 1
        for i in range(len(passwords[index:])):
            passwords[i].previous_hash = passwords[previous_index].hash
            passwords[i].calculate_hash()
            previous_index += 1


def update_password_params(password_params: password.PasswordBlueprint, master_password, index):
    global passwords

    if password_params.url == "":
        cache_url = passwords[index].url
    else:
        cache_url = password_params.url

    cache_password = password.Password(cache_url, password_params.password, passwords[index].hash, master_password)
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
    return dictionary_list


def database_decode(dictionary_list: [{}], master_password):
    global passwords
    cache_passwords: List[password.Password] = []
    for dat in dictionary_list:
        cache_password = password.Password(dat["url"], dat["password"], dat["previous_hash"], master_password)
        cache_passwords.append(cache_password)
    passwords = cache_passwords


def save_database_to_file(algorithm_mode, key_length):
    file_manager.write_file(integrity_manager.encrypt_database(database_encode(), algorithm_mode, key_length))

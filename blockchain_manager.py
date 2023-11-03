import password
from typing import List

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

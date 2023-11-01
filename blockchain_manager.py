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
    passwords.pop(index)
    recount_blockchain()


def recount_blockchain():
    global passwords

    cache_passwords: List[password.Password] = []
    cache_passwords.append(passwords[0])
    cache_passwords[0].previous_hash = ""
    cache_passwords[0].hash = cache_passwords[0].calculate_hash()
    count = 0
    for dat in passwords[2:]:
        dat.previous_hash = cache_passwords[count].hash
        dat.hash = dat.calculate_hash()
        cache_passwords.append(dat)
        count += 1

    passwords = cache_passwords

from password import Password
from typing import List
import pickle


file_path = 'database.pkl'
saved_hash = ""


def get_saved_hash():
    return saved_hash


def write_file(encrypted_database):
    file = open(file_path, 'wb')
    pickle.dump(encrypted_database, file)
    file.close()


def open_file():
    file = open(file_path, 'rb')
    data = pickle.load(file)
    file.close()
    return data


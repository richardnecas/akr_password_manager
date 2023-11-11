from password import Password
from typing import List
import pickle
import os


database_path = 'database.dat'
metadata_path = 'metadata.dat'
private_key_path = 'private.pem'
public_key_path = 'public.pem'
saved_hash = ""


def get_saved_hash():
    return saved_hash


def get_metadata():
    return {}


def open_file(file_path):
    with open(file_path, 'rb') as file_to_open:
        return file_to_open.read()


def write_file(encrypted_data, file_path):
    with open(file_path, 'wb') as file_to_save:
        file_to_save.write(encrypted_data)

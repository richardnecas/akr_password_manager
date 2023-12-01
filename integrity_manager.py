import base64
import hashlib
import os
from typing import List
import password
import utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import file_manager
import json
import binascii
import time
from logger import make_log, LogMessage

metadata = {
    "mode": 0,
    "key_length": 0,
    "login": "",
    "password_hash": "",
    "nonce": "",
    "salt": "",
    "tag": "",
    "crc": 0,
    "hash_stamp": ""
}

old_params = {
    "mode": 0,
    "key_length": 0
}

next_session_key = bytes()

rsa_password = [int(format(ord('d'))) ^ 1, int(format(ord('#'))) ^ 2, int(format(ord('R'))) ^ 3, int(format(ord('2'))) ^ 4,
                int(format(ord('O'))) ^ 5, int(format(ord('x'))) ^ 6, int(format(ord('d'))) ^ 7, int(format(ord('T'))) ^ 8]
'''print(rsa_password)
count = 1
for dat in rsa_password:
    out = dat ^ count
    print(chr(out))
    count += 1'''


def get_mode():
    return metadata["mode"]


def get_key_length():
    return metadata["key_length"]


def set_mode(mode):
    metadata["mode"] = mode


def set_key_length(key_length):
    metadata["key_length"] = key_length


def set_login(login):
    metadata["login"] = login


def get_login():
    return metadata["login"]


def set_password_hash(login, pwd):
    global metadata
    cache = login + pwd
    metadata["password_hash"] = hashlib.sha256(cache.encode('utf-8')).hexdigest()


def check_pwd_hash(login, pwd):
    cache = login + pwd
    if hashlib.sha256(cache.encode('utf-8')).hexdigest() == metadata["password_hash"]:
        return True
    return False


def generate_number(byte_length):
    return os.urandom(byte_length)


def run_integrity_check(encoded_database, passwords):
    if check_blockchain(passwords) and check_crc(encoded_database) and check_hash(encoded_database):
        return True
    return False


def derive_key(master_password, key_length, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=key_length,
                     salt=salt,
                     iterations=400000,
                     backend=default_backend())
    return kdf.derive(master_password.encode('utf-8'))


def generate_next_session_key(master_password):
    global next_session_key
    metadata["salt"] = generate_number(16).hex()
    next_session_key = derive_key(master_password, old_params["key_length"], bytes.fromhex(metadata["salt"]))


def check_blockchain(unchecked_list: List[password.Password]):
    prev_hash = ""
    for block in unchecked_list:
        if block.hash != block.calculate_hash() or block.previous_hash != prev_hash:
            return False
        prev_hash = block.hash
    return True


def check_crc(data):
    if count_crc(data) == metadata["crc"]:
        return True
    return False


def count_crc(data):
    return binascii.crc32(data) & 0xffffffff


def check_hash(data):
    if hashlib.sha256(data).hexdigest() == metadata["hash_stamp"]:
        return True
    return False


def change_next_session_key(master_password):
    global next_session_key
    metadata["salt"] = generate_number(16).hex()
    next_session_key = derive_key(master_password, metadata["key_length"], bytes.fromhex(metadata["salt"]))


def check_params():
    if metadata["mode"] != old_params["mode"] or metadata["key_length"] != old_params["key_length"]:
        return False
    return True


def encrypt_database(encoded_database: [{}]):
    global metadata
    metadata["crc"] = count_crc(encoded_database)
    metadata["hash_stamp"] = hashlib.sha256(encoded_database).hexdigest()
    return_array = []
    if metadata["mode"] == 0:
        return_array = aes_gcm_encrypt(encoded_database)
        metadata["nonce"] = return_array[1].hex()
        metadata["tag"] = return_array[2].hex()
    if metadata["mode"] == 1:
        return_array = camellia_encrypt(encoded_database)
        metadata["nonce"] = return_array[1].hex()
    if metadata["mode"] == 2:
        return_array = fernet_encrypt(encoded_database)
    save_metadata()
    return return_array[0]


def decrypt_database(encrypted_database, master_password):
    #load_metadata()
    if metadata["mode"] == 0:
        return aes_gcm_decrypt(encrypted_database, metadata["key_length"], bytes.fromhex(metadata["salt"]), bytes.fromhex(metadata["nonce"]), bytes.fromhex(metadata["tag"]), master_password)
    if metadata["mode"] == 1:
        return camellia_decrypt(encrypted_database, metadata["key_length"], bytes.fromhex(metadata["salt"]), bytes.fromhex(metadata["nonce"]), master_password)
    if metadata["mode"] == 2:
        return fernet_decrypt(encrypted_database, metadata["key_length"], bytes.fromhex(metadata["salt"]), master_password)


def aes_gcm_encrypt(database: [{}]):
    nonce = generate_number(24)

    padder = sym_padding.PKCS7(128).padder()
    padded_database = padder.update(database) + padder.finalize()
    cipher = Cipher(algorithms.AES(next_session_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(padded_database) + encryptor.finalize()

    tag = encryptor.tag
    return [encrypted_data, nonce, tag]


def aes_gcm_decrypt(database, key_length, salt, nonce, tag, master_password):
    cipher = Cipher(algorithms.AES(derive_key(master_password, key_length, salt)), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(decryptor.update(database) + decryptor.finalize()) + unpadder.finalize()


def camellia_encrypt(database: [{}]):
    nonce = generate_number(16)

    padder = sym_padding.PKCS7(128).padder()
    padded_database = padder.update(database) + padder.finalize()
    cipher = Cipher(algorithms.Camellia(next_session_key), modes.CBC(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    return [encryptor.update(padded_database) + encryptor.finalize(), nonce]


def camellia_decrypt(database, key_length, salt, nonce, master_password):
    cipher = Cipher(algorithms.Camellia(derive_key(master_password, key_length, salt)), modes.CBC(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(decryptor.update(database) + decryptor.finalize()) + unpadder.finalize()


def fernet_encrypt(database: [{}]):
    f = Fernet(base64.urlsafe_b64encode(next_session_key))
    return [f.encrypt(database)]


def fernet_decrypt(database, key_length, salt, master_password):
    f = Fernet(base64.urlsafe_b64encode(derive_key(master_password, key_length, salt)))
    return f.decrypt(database)


def encrypt_metadata(metadata_to_save: {}):
    public_key = serialization.load_pem_public_key(file_manager.open_file(utils.FilePath.public.value), backend=default_backend())
    return public_key.encrypt(json.dumps(metadata_to_save).encode('utf-8'), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                                         algorithm=hashes.SHA256(),
                                                                                         label=None))


def decrypt_metadata(metadata_from_file):
    private_key = serialization.load_pem_private_key(file_manager.open_file(utils.FilePath.private.value),
                                                     backend=default_backend(),
                                                     password=len(rsa_password).to_bytes(byteorder='big', length=16))
    decrypted_message = private_key.decrypt(metadata_from_file, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                             algorithm=hashes.SHA256(),
                                                                             label=None))
    return json.loads(decrypted_message.decode('utf-8'))


def save_metadata():
    generate_rsa_keys()
    file_manager.write_file(encrypt_metadata(metadata), utils.FilePath.metadata.value)


def load_metadata():
    global metadata, old_params
    metadata = decrypt_metadata(file_manager.open_file(utils.FilePath.metadata.value))
    old_params["mode"] = metadata["mode"]
    old_params["key_length"] = metadata["key_length"]


def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    file_manager.write_file(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                      encryption_algorithm=serialization.BestAvailableEncryption(
                                                          len(rsa_password).to_bytes(byteorder='big', length=16))),
                            utils.FilePath.private.value)
    file_manager.write_file(private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo),
                            utils.FilePath.public.value)



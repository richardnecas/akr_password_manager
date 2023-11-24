import base64
import hashlib
import os
from typing import List
import password
import utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as kktina
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import file_manager
import json
import time
from logger import make_log, LogMessage

metadata = {
    "mode": 0,
    "key_length": 32,
    "login": "",
    "password_hash": "",
    "nonce": "",
    "crc": 0,
    "salt": "",
    "tag": ""
}

rsa_password = [int(format(ord('d'))) ^ 1, int(format(ord('#'))) ^ 2, int(format(ord('R'))) ^ 3, int(format(ord('2'))) ^ 4,
                int(format(ord('O'))) ^ 5, int(format(ord('x'))) ^ 6, int(format(ord('d'))) ^ 7, int(format(ord('T'))) ^ 8]
'''print(rsa_password)
count = 1
for dat in rsa_password:
    out = dat ^ count
    print(chr(out))
    count += 1'''


def generate_number(byte_length):
    return os.urandom(byte_length)


def run_integrity_check():
    if check_blockchain() and check_crc() and check_hash():
        return True
    return False


def derive_key(master_password, key_length, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=key_length,
                     salt=salt,
                     iterations=100000,
                     backend=default_backend())
    return kdf.derive(master_password.encode('utf-8'))


def check_blockchain(unchecked_list: List[password.Password]):
    prev_hash = ""
    for block in unchecked_list:
        if block.hash != block.calculate_hash() or block.previous_hash != prev_hash:
            return False
        prev_hash = block.hash
    return True


def check_crc():
    return None


def check_hash():
    return None


def encrypt_database(encoded_database: [{}], algorithm, key_length, master_password):
    global metadata
    if algorithm == 0:
        return_array = aes_gcm_encrypt(encoded_database, key_length, master_password)
    elif algorithm == 1:
        return
    else:
        return
    metadata["nonce"] = return_array[1].hex()
    metadata["salt"] = return_array[2].hex()
    metadata["tag"] = return_array[3].hex()
    save_metadata()
    return return_array[0]


def decrypt_database(encrypted_database, master_password):
    load_metadata()
    if metadata["mode"] == 0:
        return aes_gcm_decrypt(encrypted_database, 32, bytes.fromhex(metadata["salt"]), bytes.fromhex(metadata["nonce"]), bytes.fromhex(metadata["tag"]), master_password)
    elif metadata["mode"] == 1:
        return
    else:
        return


def aes_gcm_encrypt(database: [{}], key_length, master_password):
    salt = generate_number(16)
    nonce = generate_number(24)

    padder = kktina.PKCS7(128).padder()
    padded_database = padder.update(database) + padder.finalize()

    cipher = Cipher(algorithms.AES(derive_key(master_password, key_length, salt)), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(padded_database) + encryptor.finalize()

    tag = encryptor.tag
    return [encrypted_data, nonce, salt, tag]


def aes_gcm_decrypt(database, key_length, salt, nonce, tag, master_password):
    cipher = Cipher(algorithms.AES(derive_key(master_password, key_length, salt)), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = kktina.PKCS7(128).unpadder()
    return unpadder.update(decryptor.update(database) + decryptor.finalize()) + unpadder.finalize()


def encrypt_metadata(metadata_to_save: {}):
    public_key = serialization.load_pem_public_key(file_manager.open_file(utils.FilePath.public.value), backend=default_backend())
    return public_key.encrypt(json.dumps(metadata_to_save).encode('utf-8'), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                                         algorithm=hashes.SHA256(),
                                                                                         label=None))


def decrypt_metadata(metadata_from_file):
    global metadata
    private_key = serialization.load_pem_private_key(file_manager.open_file(utils.FilePath.private.value),
                                                     backend=default_backend(),
                                                     password=len(rsa_password).to_bytes(byteorder='big', length=16))
    decrypted_message = private_key.decrypt(metadata_from_file, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                             algorithm=hashes.SHA256(),
                                                                             label=None))
    metadata = json.loads(decrypted_message.decode('utf-8'))


def save_metadata():
    generate_rsa_keys()
    file_manager.write_file(encrypt_metadata(metadata), utils.FilePath.metadata.value)


def load_metadata():
    decrypt_metadata(file_manager.open_file(utils.FilePath.metadata.value))


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


'''generate_rsa_keys()
rnd_num = generate_number(32).hex()
print(rnd_num)
metadata["nonce"] = rnd_num
save_metadata()
load_metadata()
print(metadata)
print(bytes.fromhex(metadata["nonce"]))'''

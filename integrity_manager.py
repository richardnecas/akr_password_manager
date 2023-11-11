import hashlib
from typing import List
import password
import utils
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import file_manager
import json

#crc, hash, recount blockchainu

metadata = {
    "mode": 0,
    "key_length": 0,
    "login": "",
    "password_hash": "",
    "random_number": 0
}

rsa_password = '3v4589gevnfhw44tp9wegh23'


def generate_number():
    return random.randint(111111, 999999)


def check_blockchain(unchecked_list: List[password.Password]):
    return None


def encrypt_database(encoded_database: [{}], algorithm, key_length, master_password):
    return None


def decrypt_database(encrypted_database, algorithm, key_length, master_password):
    return None


def prepare_metadata(master_password):
    saved_rnd_number = int(metadata["random_number"])
    metadata_to_save = metadata
    metadata_to_save["random_number"] = encrypt_random_number(saved_rnd_number, master_password)
    return metadata_to_save


def load_metadata(metadata_list: {}, master_password):
    global metadata
    metadata["mode"] = metadata_list["mode"]
    metadata["key_length"] = metadata_list["key_length"]
    metadata["login"] = metadata_list["login"]
    metadata["password_hash"] = metadata_list["password_hash"]
    metadata["random_number"] = decrypt_random_number(metadata_list["random_number"], master_password)


def encrypt_random_number(rnd_number: int, master_password):
    bytes_number = rnd_number.to_bytes(length=16, byteorder='big')
    cipher = Cipher(algorithms.AES(bytes.fromhex(hashlib.sha256(master_password.encode('utf-8')).hexdigest())), modes.ECB())
    encryptor = cipher.encryptor()
    return int.from_bytes(encryptor.update(bytes_number) + encryptor.finalize(), byteorder='big')


def decrypt_random_number(encrypted_number: int, master_password):
    bytes_number = encrypted_number.to_bytes(length=16, byteorder='big')
    cipher = Cipher(algorithms.AES(bytes.fromhex(hashlib.sha256(master_password.encode('utf-8')).hexdigest())), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted_number = decryptor.update(bytes_number) + decryptor.finalize()
    return int.from_bytes(decrypted_number, byteorder='big')


def encrypt_metadata(metadata_to_save: {}):
    public_key = serialization.load_pem_public_key(file_manager.open_file(utils.FilePath.public), backend=default_backend())
    return public_key.encrypt(metadata_to_save, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                             algorithm=hashes.SHA256(),
                                                             label=None))


def save_metadata(master_password):
    metadata_to_save = prepare_metadata(master_password)
    file_manager.write_file(encrypt_metadata(metadata_to_save), utils.FilePath.metadata)


def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    file_manager.write_file(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                      encryption_algorithm=serialization.BestAvailableEncryption(
                                                          len(rsa_password).to_bytes(byteorder='big', length=16))),
                            utils.FilePath.private)
    file_manager.write_file(private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo),
                            utils.FilePath.public)


metadata["random_number"] = generate_number()
save_metadata("silneheslo")

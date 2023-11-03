import hashlib
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class PasswordBlueprint:
    def __init__(self, url, password):
        self.url = url
        self.password = password


class Password:
    def __init__(self, url, password, previous_hash, master_password):
        self.url = url
        self.previous_hash = previous_hash
        self.timestamp = time.time()
        self.password = self.encrypt_password(master_password, password)
        self.hash = self.calculate_hash()
        
    def calculate_hash(self):
        cache_str = self.url + str(self.password) + self.previous_hash + str(self.timestamp)
        return hashlib.sha256(cache_str.encode("utf-8")).hexdigest()
    
    def encrypt_password(self, master_password, password):
        padder = padding.PKCS7(128).padder()
        padded_password = padder.update(password.encode('utf-8')) + padder.finalize()
        
        hash_input = self.url + master_password
        #print(hashlib.sha256(hash_input.encode('utf-8')).hexdigest().encode('utf-8')) #to check the length of byted hash, parameter doesn't work for en/decryption
        cipher = Cipher(algorithms.AES(bytes.fromhex(hashlib.sha256(hash_input.encode('utf-8')).hexdigest())), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(padded_password) + encryptor.finalize()
        
    def decrypt_password(self, master_password):
        hash_input = self.url + master_password
        cipher = Cipher(algorithms.AES(bytes.fromhex(hashlib.sha256(hash_input.encode('utf-8')).hexdigest())), modes.ECB())
        
        decryptor = cipher.decryptor()
        padded_decrypted_message = decryptor.update(self.password) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_decrypted_message) + unpadder.finalize()


password = "Hello world"
passObj = Password("web.cz", password, "", "totojesilneheslo")
print(passObj.password)
print(passObj.decrypt_password("totojesilneheslo"))

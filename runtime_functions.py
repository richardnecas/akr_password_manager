import blockchain_manager
import integrity_manager
import authenticator


def get_database():
    return blockchain_manager.get_database()


def set_mode(mode):
    integrity_manager.set_mode(mode)


def set_key_length(key_length):
    integrity_manager.set_key_length(key_length)


def get_login():
    return integrity_manager.get_login()


def add_password(new_pass):
    blockchain_manager.add_password(new_pass)


def delete_password(index):
    blockchain_manager.delete_password(index)


def change_password(new_pass, index):
    blockchain_manager.change_password(new_pass, index)


def check_params():
    return integrity_manager.check_params()


def change_next_session_key(master_password):
    integrity_manager.change_next_session_key(master_password)


def save_database():
    blockchain_manager.save_database_to_file()


def load_database(master_password):
    return blockchain_manager.load_database_from_file(master_password)


def set_new_user(login, password):
    integrity_manager.set_login(login)
    integrity_manager.set_password_hash(login, password)


def get_code(login, password):
    return authenticator.get_image(login, password)


def authenticate_second_factor(pin, password):
    if authenticator.authenticate(pin, password) == 'True':
        return True
    return False


def authenticate_first_factor(login, password):
    if integrity_manager.check_pwd_hash(login, password):
        return True
    return False


def load_metadata():
    integrity_manager.load_metadata()


def set_params(text):
    if text == 'AES':
        integrity_manager.set_mode(0)
    elif text == 'Camelia':
        integrity_manager.set_mode(1)
    elif text == 'Fernet':
        integrity_manager.set_mode(2)
        integrity_manager.set_key_length(32)
    elif text == '128':
        integrity_manager.set_key_length(16)
    elif text == '192':
        integrity_manager.set_key_length(24)
    elif text == '256':
        integrity_manager.set_key_length(32)


def get_mode():
    return integrity_manager.get_mode()


def get_key_length():
    return integrity_manager.get_key_length()


def generate_next_session_key(master_password):
    integrity_manager.generate_next_session_key(master_password)

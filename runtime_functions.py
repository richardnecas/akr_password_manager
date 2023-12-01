import blockchain_manager
import integrity_manager
import authenticator


def get_database():
    return blockchain_manager.get_database()


def set_mode(mode):
    integrity_manager.set_mode(mode)


def set_key_length(key_length):
    integrity_manager.set_key_length(key_length)


def add_password(new_pass):
    blockchain_manager.add_password(new_pass)


def delete_password(index):
    blockchain_manager.delete_password(index)


def change_password(new_pass, index):
    blockchain_manager.change_password(new_pass, index)


def save_database():
    if not integrity_manager.check_params():
        integrity_manager.change_next_session_key(input("Enter master password "))
    blockchain_manager.save_database_to_file()


def load_database(master_password):
    return load_database(master_password)


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


def app_innit():
    return

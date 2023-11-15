def open_file(file_path):
    with open(file_path, 'rb') as file_to_open:
        return file_to_open.read()


def write_file(encrypted_data, file_path):
    with open(file_path, 'wb') as file_to_save:
        file_to_save.write(encrypted_data)

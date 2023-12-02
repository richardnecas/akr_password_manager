import os
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QListWidget, QListWidgetItem, QDialog, QLabel, \
    QLineEdit, QVBoxLayout, QWidget, QHBoxLayout, QDesktopWidget, QGridLayout
from PyQt5.QtCore import Qt, QSize, pyqtSignal, QCoreApplication
import runtime_functions
from password import PasswordBlueprint
from PyQt5.QtGui import QFont, QPixmap
from utils import FilePath

button_font = QFont("Calibri")
button_font.setPointSize(13)
item_font = QFont("Calibri")
item_font.setPointSize(11)


class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.params = Parameters()
        self.pwd_in = PasswordInput()

        self.setWindowTitle('Password Manager')
        self.resize(450, 600)  # setting main window size

        self.widget = QWidget()
        self.setCentralWidget(self.widget)

        self.layout = QHBoxLayout()
        self.widget.setLayout(self.layout)

        self.list_widget = QListWidget(self)
        self.list_widget.setIconSize(QSize(200, 50))  # Increase height of QListWidgetItem
        self.list_widget.setSpacing(10)
        self.list_widget.setFont(item_font)

        self.center()

        self.list_widget.setStyleSheet("""
            QListWidget::item {
                border: 2px solid black;
                border-radius: 10px;
                padding: 5px;
                background-color: rgba(50,10,80,0.4);
            }
        """)

        self.layout.addWidget(self.list_widget)

        self.buttons_layout = QVBoxLayout()

        self.button1 = QPushButton('Add', self)
        self.button1.clicked.connect(self.open_input_window)
        self.button1.setFont(button_font)
        self.buttons_layout.addWidget(self.button1)

        self.button2 = QPushButton('Delete', self)
        self.button2.clicked.connect(self.delete_selected_item)
        self.button2.setFont(button_font)
        self.buttons_layout.addWidget(self.button2)

        self.button3 = QPushButton('Change', self)
        self.button3.clicked.connect(self.open_update_window)
        self.button3.setFont(button_font)
        self.buttons_layout.addWidget(self.button3)

        self.button4 = QPushButton('Parameters', self)
        self.button4.clicked.connect(self.open_param_window)
        self.button4.setFont(button_font)
        self.buttons_layout.addWidget(self.button4)

        self.button5 = QPushButton('Save && Close', self)
        self.button5.clicked.connect(self.save_database)
        self.button5.setFont(button_font)
        self.buttons_layout.addWidget(self.button5)

        self.padding = QLabel(self)
        self.padding.setFixedHeight(80)
        self.buttons_layout.addWidget(self.padding)

        self.parameters = QLabel(runtime_functions.get_mode_text() + ' | ' + str(runtime_functions.get_key_length() * 8), self)
        self.parameters.setFont(button_font)
        self.parameters.setFixedHeight(20)
        self.buttons_layout.addWidget(self.parameters)

        self.layout.addLayout(self.buttons_layout)

        if len(runtime_functions.get_database()) > 0:
            for item in runtime_functions.get_database():
                self.list_widget.addItem(QListWidgetItem(item.url + '\n\t' + item.password))

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def open_input_window(self):
        self.input_window = InputWindow()
        self.input_window.submitted.connect(self.handle_input_submission)
        self.input_window.show()

    def open_update_window(self):
        list_items = self.list_widget.selectedItems()
        if list_items:  # Check if any item is selected
            selected_item = list_items[0]  # Get the first selected item
            index = self.list_widget.row(selected_item)
            pwd = runtime_functions.get_database()[index]
            url, password = pwd.url, pwd.password
            self.update_window = InputWindow(url, password)
            self.update_window.submitted.connect(
                lambda url, password: self.handle_update_submission(url, password, index))
            self.update_window.show()

    def handle_input_submission(self, url, password):
        pwd = PasswordBlueprint(url, password)
        runtime_functions.add_password(pwd)
        self.list_widget.addItem(QListWidgetItem(url + '\n\t' + password))

    def handle_update_submission(self, url, password, index):
        pwd_obj = PasswordBlueprint(url, password)
        runtime_functions.change_password(pwd_obj, index)
        self.list_widget.item(index).setText(url + '\n\t' + password)

    def delete_selected_item(self):
        list_items = self.list_widget.selectedItems()
        if not list_items: return
        for item in list_items:
            runtime_functions.delete_password(self.list_widget.row(item))
            self.list_widget.takeItem(self.list_widget.row(item))

    def open_param_window(self):
        self.params.show()

    def save_database(self):
        if not runtime_functions.check_params():
            self.pwd_in.show()
            return
        runtime_functions.save_database()
        QCoreApplication.instance().quit()

    def refresh_params(self):
        self.parameters.setText(runtime_functions.get_mode_text() + ' | ' + str(runtime_functions.get_key_length() * 8))


class Login(QDialog):
    submitted = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.pin_input = None

        self.setWindowTitle('Log-in')

        self.label_login = QLabel('Login:', self)
        self.label_login.setFont(button_font)
        self.url_field = QLineEdit(self)
        self.url_field.setFont(button_font)

        self.label_password = QLabel('Password:', self)
        self.label_password.setFont(button_font)
        self.password_field = QLineEdit(self)
        self.password_field.setFont(button_font)

        self.button_save = QPushButton('Login', self)
        self.button_save.setFont(button_font)
        self.button_save.clicked.connect(self.save)

        layout = QVBoxLayout(self)
        layout.addWidget(self.label_login)
        layout.addWidget(self.url_field)
        layout.addWidget(self.label_password)
        layout.addWidget(self.password_field)
        layout.addWidget(self.button_save)

    def save(self):
        if os.path.isfile(FilePath.metadata.value):
            runtime_functions.load_metadata()
        login = self.url_field.text()
        password = self.password_field.text()
        if runtime_functions.authenticate_first_factor(login, password):
            self.pin_input = PinInput(password)
            self.pin_input.show()


class WelcomeScreen(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Welcome!')

        self.label_signup = QLabel('First time here', self)
        self.label_signup.setFont(button_font)
        self.label_login = QLabel('Already been here', self)
        self.label_login.setFont(button_font)

        self.button_signup = QPushButton('Sign-up', self)
        self.button_signup.setFont(button_font)
        self.button_signup.clicked.connect(self.open_signup_window)
        self.button_login = QPushButton('Log-in', self)
        self.button_login.setFont(button_font)
        self.button_login.clicked.connect(self.open_login_window)

        layout = QVBoxLayout(self)
        layout.addWidget(self.label_signup)
        layout.addWidget(self.button_signup)
        layout.addWidget(self.label_login)
        layout.addWidget(self.button_login)

        if os.path.isfile(FilePath.metadata.value):
            self.label_signup.setVisible(False)
            self.button_signup.setVisible(False)
        else:
            self.label_login.setVisible(False)
            self.button_login.setVisible(False)

    def open_login_window(self):
        login_window.show()
        self.close()

    def open_signup_window(self):
        signup_window.show()
        self.close()


class Signup(QDialog):
    submitted = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle('Sign-up')

        self.label_login = QLabel('Login:', self)
        self.label_login.setFont(button_font)
        self.login_field = QLineEdit(self)
        self.login_field.setFont(button_font)

        self.label_password = QLabel('Password:', self)
        self.label_password.setFont(button_font)
        self.password_field = QLineEdit(self)
        self.password_field.setFont(button_font)

        self.button_save = QPushButton('Sign-up', self)
        self.button_save.setFont(button_font)
        self.button_save.clicked.connect(self.save)

        layout = QVBoxLayout(self)
        layout.addWidget(self.label_login)
        layout.addWidget(self.login_field)
        layout.addWidget(self.label_password)
        layout.addWidget(self.password_field)
        layout.addWidget(self.button_save)

    def save(self):
        global code_window
        login = self.login_field.text()
        password = self.password_field.text()
        if login != "" and password != "":
            runtime_functions.set_new_user(login, password)
            self.close()
            code_window = Image(runtime_functions.get_code(login, password))
            code_window.show()


class Image(QMainWindow):
    def __init__(self, image):
        super(Image, self).__init__()

        self.setWindowTitle('Scan me!')
        self.center()

        # Create a QLabel to display the image
        image_label = QLabel(self)
        pixmap = QPixmap()
        pixmap.loadFromData(image)
        image_label.setPixmap(pixmap)

        self.close_button = QPushButton('Continue', self)
        self.close_button.setFont(button_font)
        self.close_button.clicked.connect(self.next)

        self.label = QLabel('Scan with Google Authenticator', self)
        self.label.setFont(button_font)

        # Set up the main window layout
        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)
        layout.addWidget(self.label, 0, Qt.AlignCenter)
        layout.addWidget(image_label)
        layout.addWidget(self.close_button)
        self.setCentralWidget(central_widget)

    def next(self):
        runtime_functions.create_folder()
        login_window.show()
        self.close()

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())


class PinInput(QDialog):
    def __init__(self, password):
        super().__init__()

        self.password = password

        self.setWindowTitle('Enter pin')

        self.label_login = QLabel('6 digit pin:', self)
        self.label_login.setFont(button_font)
        self.login_field = QLineEdit(self)
        self.login_field.setFont(button_font)

        self.button_save = QPushButton('Log-in', self)
        self.button_save.setFont(button_font)
        self.button_save.clicked.connect(self.save)

        layout = QVBoxLayout(self)
        layout.addWidget(self.label_login)
        layout.addWidget(self.login_field)
        layout.addWidget(self.button_save)

    def save(self):
        global main
        if runtime_functions.authenticate_second_factor(self.login_field.text(), self.password):
            if os.path.isfile(FilePath.database.value):
                if runtime_functions.load_database(self.password):
                    runtime_functions.generate_next_session_key(self.password)
            main = Main()
            main.show()
            self.close()
            login_window.close()


class InputWindow(QDialog):
    submitted = pyqtSignal(str, str)

    def __init__(self, url='', password=''):
        super().__init__()

        self.setWindowTitle('')

        self.label_url = QLabel('URL:', self)
        self.label_url.setFont(button_font)
        self.url_field = QLineEdit(url, self)
        self.url_field.setFont(button_font)

        self.label_password = QLabel('Password:', self)
        self.label_password.setFont(button_font)
        self.password_field = QLineEdit(password, self)
        self.password_field.setFont(button_font)

        self.button_save = QPushButton('Save', self)
        self.button_save.setFont(button_font)
        self.button_save.clicked.connect(self.save)

        layout = QVBoxLayout(self)
        layout.addWidget(self.label_url)
        layout.addWidget(self.url_field)
        layout.addWidget(self.label_password)
        layout.addWidget(self.password_field)
        layout.addWidget(self.button_save)

    def save(self):
        self.submitted.emit(self.url_field.text(), self.password_field.text())
        self.close()


class Parameters(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Set parameters')

        self.btn1 = QPushButton('AES', self)
        self.btn1.setFont(button_font)
        self.btn1.clicked.connect(lambda: self.on_button_click(self.btn1.text()))
        self.btn2 = QPushButton('Camelia', self)
        self.btn2.setFont(button_font)
        self.btn2.clicked.connect(lambda: self.on_button_click(self.btn2.text()))
        self.btn3 = QPushButton('Fernet', self)
        self.btn3.setFont(button_font)
        self.btn3.clicked.connect(lambda: self.on_button_click(self.btn3.text()))
        self.btn4 = QPushButton('128', self)
        self.btn4.setFont(button_font)
        self.btn4.clicked.connect(lambda: self.on_button_click(self.btn4.text()))
        self.btn5 = QPushButton('192', self)
        self.btn5.setFont(button_font)
        self.btn5.clicked.connect(lambda: self.on_button_click(self.btn5.text()))
        self.btn6 = QPushButton('256', self)
        self.btn6.setFont(button_font)
        self.btn6.clicked.connect(lambda: self.on_button_click(self.btn6.text()))

        self.grid = QGridLayout()
        self.grid.addWidget(self.btn1, 0, 0)
        self.grid.addWidget(self.btn2, 0, 1)
        self.grid.addWidget(self.btn3, 0, 2)
        self.grid.addWidget(self.btn4, 1, 0)
        self.grid.addWidget(self.btn5, 1, 1)
        self.grid.addWidget(self.btn6, 1, 2)

        if runtime_functions.get_mode() == 2:
            self.btn4.setVisible(False)
            self.btn5.setVisible(False)
            self.btn6.setVisible(False)

        self.setLayout(self.grid)

    def on_button_click(self, text):
        runtime_functions.set_params(text)
        self.refresh()
        main.refresh_params()

    def refresh(self):
        if runtime_functions.get_mode() == 2:
            self.btn4.setVisible(False)
            self.btn5.setVisible(False)
            self.btn6.setVisible(False)
        else:
            self.btn4.setVisible(True)
            self.btn5.setVisible(True)
            self.btn6.setVisible(True)


class PasswordInput(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Enter password!')

        self.label_password = QLabel('Parameters changed, enter password', self)
        self.label_password.setFont(button_font)
        self.password_field = QLineEdit(self)
        self.password_field.setFont(button_font)

        self.button_save = QPushButton('Save', self)
        self.button_save.setFont(button_font)
        self.button_save.clicked.connect(self.save)

        layout = QVBoxLayout(self)
        layout.addWidget(self.label_password)
        layout.addWidget(self.password_field)
        layout.addWidget(self.button_save)

    def save(self):
        if runtime_functions.authenticate_first_factor(runtime_functions.get_login(), self.password_field.text()):
            runtime_functions.change_next_session_key(self.password_field.text())
            runtime_functions.save_database()
            self.close()
            QCoreApplication.instance().quit()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main = None
    login_window = Login()
    signup_window = Signup()
    welcome_window = WelcomeScreen()
    welcome_window.show()
    code_window = None

    sys.exit(app.exec_())

import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QListWidget, QListWidgetItem, QDialog, QLabel, \
    QLineEdit, QVBoxLayout, QWidget, QHBoxLayout, QDesktopWidget
from PyQt5.QtCore import Qt, QSize, pyqtSignal
import runtime_functions
from password import PasswordBlueprint
from PyQt5.QtGui import QFont, QPixmap
import blockchain_manager

button_font = QFont("Calibri")
button_font.setPointSize(13)
item_font = QFont("Calibri")
item_font.setPointSize(11)


class Main(QMainWindow):
    def __init__(self):
        super().__init__()

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
            print(blockchain_manager.database_encode())
            self.list_widget.takeItem(self.list_widget.row(item))


class Login(QDialog):
    submitted = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.pin_input = None

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
        login = self.url_field.text()
        password = self.password_field.text()
        test = runtime_functions.authenticate_first_factor(login, password)
        print(test)
        if test:
            self.pin_input = PinInput(password)
            self.pin_input.show()


class WelcomeScreen(QDialog):
    def __init__(self):
        super().__init__()

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
            code_window = Image(runtime_functions.get_code(login, password))
            code_window.show()


class Image(QMainWindow):
    def __init__(self, image):
        super().__init__()

        # Create a QLabel to display the image
        image_label = QLabel(self)
        pixmap = QPixmap()
        pixmap.loadFromData(image)
        image_label.setPixmap(pixmap)

        self.close_button = QPushButton('Continue', self)
        self.close_button.setFont(button_font)
        self.close_button.clicked.connect(self.next)

        # Set up the main window layout
        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)
        layout.addWidget(image_label)
        layout.addWidget(self.close_button)
        self.setCentralWidget(central_widget)

    def next(self):
        login_window.show()
        self.close()
        signup_window.close()


class PinInput(QDialog):
    def __init__(self, password):
        super().__init__()

        self.password = password

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
        if runtime_functions.authenticate_second_factor(self.login_field.text(), self.password):
            main.show()
            self.close()
            login_window.close()


class InputWindow(QDialog):
    submitted = pyqtSignal(str, str)

    def __init__(self, url='', password=''):
        super().__init__()

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


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main = Main()
    login_window = Login()
    signup_window = Signup()
    welcome_window = WelcomeScreen()
    welcome_window.show()
    code_window = None

    sys.exit(app.exec_())

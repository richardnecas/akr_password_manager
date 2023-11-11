import sys

from PyQt5.QtCore import QByteArray
from PyQt5.QtWidgets import QApplication, QLabel, QMainWindow, QVBoxLayout, QWidget
from PyQt5.QtGui import QPixmap
import requests
from bs4 import BeautifulSoup


class ImageViewer(QMainWindow):
    def __init__(self, image_url):
        super().__init__()

        # Fetch the image content
        image_response = requests.get(image_url)
        image_content = QByteArray(image_response.content)

        # Create a QLabel to display the image
        image_label = QLabel(self)
        pixmap = QPixmap()
        pixmap.loadFromData(image_content)
        image_label.setPixmap(pixmap)

        # Set up the main window layout
        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)
        layout.addWidget(image_label)
        self.setCentralWidget(central_widget)


def main():
    # Replace 'https://example.com' with the actual URL of the website
    url = 'https://www.authenticatorapi.com/pair.aspx?AppName=MyApp&AppInfo=John&SecretCode=12345678BXYT'

    # Fetch the HTML content of the website
    response = requests.get(url)
    html_content = response.text

    # Parse the HTML using BeautifulSoup
    soup = BeautifulSoup(html_content, 'html.parser')

    # Find the image tag or any other tag containing the image URL
    # For example, find the first image tag: <img src="...">
    image_tag = soup.find('img')

    if image_tag:
        # Extract the URL from the 'src' attribute
        image_url = image_tag['src']

        # Create the Qt application
        app = QApplication(sys.argv)

        # Create and show the image viewer window
        viewer = ImageViewer(image_url)
        viewer.show()

        # Start the Qt event loop
        sys.exit(app.exec_())
    else:
        print("No image found on the webpage.")


if __name__ == "__main__":
    main()

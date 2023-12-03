from PyQt5.QtCore import QByteArray
import requests
import hashlib
from bs4 import BeautifulSoup


def get_image(login, password):
    url = 'https://www.authenticatorapi.com/pair.aspx?AppName=PasswordManager&AppInfo=' + login + '&SecretCode=' + hashlib.sha256(password.encode('utf-8')).hexdigest()
    response = requests.get(url)
    html_content = response.text
    soup = BeautifulSoup(html_content, 'html.parser')
    image_tag = soup.find('img')
    image_url = image_tag['src']
    image_response = requests.get(image_url)
    return QByteArray(image_response.content)


def authenticate(pin, password):
    url = 'https://www.authenticatorApi.com/Validate.aspx?Pin=' + str(pin) + '&SecretCode=' + hashlib.sha256(password.encode('utf-8')).hexdigest()
    response = requests.get(url)
    return response.text


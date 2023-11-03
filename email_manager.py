import asyncore
from smtpd import SMTPServer
import smtplib
from email.message import EmailMessage

class MySMTPServer(SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data):
        print(f"Received email from: {mailfrom}")
        print(f"Recipient addresses: {rcpttos}")
        print(f"Email data: {data}")

# Set the server address and port
server_address = ('localhost', 1025)  # Change the hostname and port as needed

# Create an instance of your custom SMTP server
smtp_server = MySMTPServer(server_address, None)

# Start the server loop to listen for incoming emails
asyncore.loop()

msg = EmailMessage()
msg.set_content("Hello, this is a test email sent from Python!")

msg['Subject'] = 'Test Email'
msg['From'] = 'no-reply@wetried.org'  # Replace with your custom email address
msg['To'] = 'rnecrnec@gmail.com'  # Replace with the recipient's email address

# Set up the SMTP server for your custom domain
smtp_server = 'localhost'  # Replace with your custom domain's SMTP server address
smtp_port = 1025  # Replace with the appropriate SMTP port (usually 587 or 465)
username = 'no-reply@wetried.org'  # Replace with your custom email address
password = 'IHaveNoIdeaWhatIamDoing'  # Replace with your email account password or use an app password

# Set up the connection to the SMTP server
server = smtplib.SMTP(smtp_server, smtp_port)
server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection

# Log in to your email account
server.login('no-reply@wetried.org', 'IHaveNoIdeaWhatIamDoing')

# Send the email
server.send_message(msg)

# Close the server connection
server.quit()
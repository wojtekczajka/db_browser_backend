import smtplib, ssl, sys
import crud
from email.message import EmailMessage

receiver_email = sys.argv[1]
port = 465  # For SSL
smtp_server = "smtp.gmail.com"
sender_email = 'dbbrowserapp@gmail.com'    
password = "zkxpkhocdmyvbsnz"

msg = EmailMessage()
msg.set_content(f'Dear user, please click on the following link to activate your account: http://yourserver.com/auth/activate/{  crud.generate_hash(receiver_email)  }')
msg['Subject'] = "DB Browser App account activation"
msg['From'] = sender_email
msg['To'] = receiver_email

context = ssl.create_default_context()
with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
    server.login(sender_email, password)
    server.send_message(msg, from_addr=sender_email, to_addrs=receiver_email)
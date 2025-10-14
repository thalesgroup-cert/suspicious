import sys
import classes.services.send_mail_service as send_mail_service


service = send_mail_service.SendMailService("localhost", 3025)
service.connect()
try:
    service.publish_email(
        "EMAIL SUBJECT",
        "sender@gmail.com",
        "imap_user@localhost",
        "<h1>Hello World!</h1>",
    )
except Exception as e:
    print(e, file=sys.stderr)
finally:
    service.close()

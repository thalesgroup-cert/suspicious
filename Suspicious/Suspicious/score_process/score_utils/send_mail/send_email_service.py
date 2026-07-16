import email.mime.multipart
import email.mime.text
import smtplib
from typing import Optional


DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1  # in seconds


class SendMailService:
    __server: smtplib.SMTP | None = None

    def __init__(
        self,
        host: str,
        port: int,
        use_tls: bool = False,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        self.__host = host
        self.__port = port
        self.__use_tls = use_tls
        self.__username = username
        self.__password = password

    def connect(self) -> None:
        self.__server = smtplib.SMTP(self.__host, self.__port)
        if self.__use_tls:
            self.__server.starttls()
        if self.__username and self.__password:
            self.__server.login(self.__username, self.__password)

    def __create_mail(
        self,
        subject: str,
        sender: str,
        recipient: str,
        html: str,
    ) -> str:
        msg = email.mime.multipart.MIMEMultipart()
        msg["From"] = sender
        msg["To"] = str(recipient)
        msg["Subject"] = str(subject)

        # Attach the HTML content to the email
        msg.attach(email.mime.text.MIMEText(html, "html"))

        return msg.as_string()

    def publish_email(
        self,
        subject: str,
        sender: str,
        recipient: str,
        html: str,
    ) -> None:
        if self.__server is None:
            raise Exception("The SMTP server is not connected.")

        message = self.__create_mail(
            subject=subject, sender=sender, recipient=recipient, html=html
        )

        self.__server.sendmail(sender, recipient, message)

    def close(self):
        if self.__server is None:
            raise Exception("The SMTP server is not connected.")

        self.__server.quit()

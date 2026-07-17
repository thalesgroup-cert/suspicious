import email.mime.multipart
import email.mime.text
import smtplib


DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1  # in seconds


def _reject_header_crlf(*values: str) -> None:
    """Guard the raw-smtplib boundary against header/SMTP injection.

    smtplib.sendmail and compat32 MIME do not sanitise embedded newlines the
    way Django's EmailMessage does, so a CR/LF in an address or subject could
    inject extra headers or SMTP commands. The bad-mail ack recipient comes
    from an inbound message's From header, so this matters here.
    """
    for value in values:
        if "\r" in value or "\n" in value:
            raise ValueError("email header value contains a newline (possible injection)")


class SendMailService:
    __server: smtplib.SMTP | None = None

    def __init__(self, host: str, port: int, login: str, password: str) -> None:
        self.__host = host
        self.__port = port
        self.__login = login
        self.__password = password

    def connect(self) -> None:
        self.__server = smtplib.SMTP(self.__host, self.__port)

    def start_tls(self) -> None:
        self.__server.starttls()

    def login(self) -> None:
        self.__server.login(user=self.__login, password=self.__password)

    def __create_mail(
        self,
        subject: str,
        sender: str,
        recipient: str,
        html: str,
    ) -> str:
        _reject_header_crlf(str(sender), str(recipient), str(subject))
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

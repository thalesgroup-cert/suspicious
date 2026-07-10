import email.mime.multipart
import email.mime.text
import smtplib


DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1


def _reject_header_crlf(*values: str) -> None:
    """Guard the raw-smtplib boundary against header/SMTP injection.

    smtplib.sendmail and compat32 MIME do not sanitise embedded newlines the
    way Django's EmailMessage does, so a CR/LF in an address or subject could
    inject extra headers or SMTP commands. Reporter addresses are normally
    already regex-clean; this is defence in depth.
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

    @classmethod
    def send_html(
        cls,
        smtp: dict,
        *,
        sender: str,
        recipient: str,
        subject: str,
        html: str,
    ) -> None:
        """Build a service from an ``smtp`` config dict and run the full
        connect -> (optional) STARTTLS -> login -> publish -> close sequence.

        Shared by every email service's ``_send_action`` so the send dance —
        and the config-key/default mapping — lives in one place.
        """
        service = cls(
            host=smtp.get("server", ""),
            port=smtp.get("port", 587),
            login=smtp.get("username", ""),
            password=smtp.get("password", ""),
        )
        service.connect()
        if smtp.get("tls"):
            service.start_tls()
        service.login()
        service.publish_email(
            subject=subject, sender=sender, recipient=recipient, html=html
        )
        service.close()

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

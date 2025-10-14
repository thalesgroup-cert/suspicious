import enum


class MailTag(enum.StrEnum):
    TODO = "To Do"
    STATUS = "Status"
    RESEND = "to_resend"

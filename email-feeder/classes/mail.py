class Mail:
    def __init__(
        self,
        sender,
        recipients,
        bcc,
        date,
        body,
        headers,
        subject,
        cc,
        attachments,
        eml,
        html,
        new_id,
        case_path,
        tags=None,
    ):
        self.sender = sender
        self.recipients = recipients
        self.date = date
        self.headers = headers
        self.body = body
        self.subject = subject
        self.cc = cc
        self.bcc = bcc
        self.attachments = attachments
        self.eml = eml
        self.html = html

        self.tags = tags

        self.new_id = new_id
        self.case_path = case_path

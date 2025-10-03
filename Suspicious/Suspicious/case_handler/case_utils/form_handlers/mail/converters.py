import logging
import os
from email.message import EmailMessage
import extract_msg

logger = logging.getLogger(__name__)

def convert_msg_to_eml(msg_path: str, eml_path: str = None) -> str:
    """
    Convert an .msg to .eml file, while keeping body, headers and attachments.
    Args:
        msg_path (str): Source Path of .msg file.
        eml_path (str, optional): Destination Path for .eml, if empty same name as the original.
    Returns:
        str: Full path of the generated .eml file
    """
    msg = extract_msg.Message(msg_path)
    msg_sender = msg.sender or ""
    msg_to = msg.to or ""
    msg_cc = msg.cc or ""
    msg_subject = msg.subject or ""
    msg_body = msg.body or ""

    email_msg = EmailMessage()
    email_msg['From'] = msg_sender
    email_msg['To'] = msg_to
    if msg_cc:
        email_msg['Cc'] = msg_cc
    email_msg['Subject'] = msg_subject
    email_msg.set_content(msg_body)

    # Ajouter les pièces jointes si présentes
    for att in msg.attachments:
        filename = att.longFilename or att.shortFilename or "attachment"
        email_msg.add_attachment(att.data, maintype='application', subtype='octet-stream', filename=filename)

    # Chemin de sortie
    if eml_path is None:
        base = os.path.splitext(msg_path)[0]
        eml_path = f"{base}.eml"

    # Sauvegarde du fichier .eml
    with open(eml_path, 'wb') as f:
        f.write(email_msg.as_bytes())

    return eml_path

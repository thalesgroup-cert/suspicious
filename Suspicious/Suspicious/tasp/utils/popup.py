from cortex_job.models import AnalyzerReport
from mail_feeder.models import MailArtifact, MailAttachment
import hashlib
import random
from datetime import datetime as dt
import string
from vt import url_id
import logging
logger = logging.getLogger(__name__)


# Pop-up data

def get_rand(id):
    '''Function used to generate a random id for the html element with id'''
    # create a random id by concatenating the given id with a hash of the current time and a random string
    rand = str(id) + hashlib.sha256(str(dt.now()).encode('utf-8')).hexdigest() + ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    # get only the digits from the hash
    digits_only = ''.join(filter(str.isdigit, rand))

    return digits_only

### Score and confidence

def get_scl(object, type):
    '''
    Get the SCL (Score, Confidence, Level) of a list of reports.

    Parameters:
    - object: The report object.
    - type: The type of report (e.g., "file", "hash", "url", "ip", "body", "header").

    Returns:
    - Tuple containing score, confidence, and level.
    '''
    score, confidence, level = 0, 0, "info"

    if type == "file":
        score = object.file_score
        confidence = object.file_confidence
        level = object.file_level

    elif type in ["hash", "url", "ip"]:
        score = object.ioc_score
        confidence = object.ioc_confidence
        level = object.ioc_level

    elif type == "body":
        score = object.body_score
        confidence = object.body_confidence
        level = object.body_level

    elif type == "header":
        score = object.header_score
        confidence = object.header_confidence
        level = object.header_level

    return score, confidence, level

### Artifacts

def get_artifacts(case_mail_artifacts):
    """
    Retrieves artifacts from the given case mail artifacts.

    Args:
        case_mail_artifacts (list): A list of case mail artifacts.

    Returns:
        dict: A dictionary containing the retrieved artifacts, their corresponding hash IDs, and information.

    """
    artifacts = []
    hashids = []
    infos = []

    for artifact in case_mail_artifacts:
        if artifact.artifact_type == 'IP':
            if artifact.artifactIsIp:
                ip_address = str(artifact.artifactIsIp.ip.address)
                artifacts.append(ip_address)
                hashids.append(get_rand(artifact.artifactIsIp.ip.id))
                infos.append([
                    artifact.artifactIsIp.ip.ioc_score,
                    artifact.artifactIsIp.ip.ioc_confidence,
                    artifact.artifactIsIp.ip.ioc_level
                ])
        elif artifact.artifact_type == 'URL':
            if artifact.artifactIsUrl:
                url_address = str(artifact.artifactIsUrl.url.address)
                artifacts.append([url_address, artifact.artifactIsUrl.url.id, url_id(url_address)])
                hashids.append(get_rand(artifact.artifactIsUrl.url.id))
                infos.append([
                    artifact.artifactIsUrl.url.ioc_score,
                    artifact.artifactIsUrl.url.ioc_confidence,
                    artifact.artifactIsUrl.url.ioc_level
                ])
        elif artifact.artifact_type == 'Hash':
            if artifact.artifactIsHash:
                hash_value = str(artifact.artifactIsHash.hash.value)
                artifacts.append(hash_value)
                hashids.append(get_rand(artifact.artifactIsHash.hash.id))
                infos.append([
                    artifact.artifactIsHash.hash.ioc_score,
                    artifact.artifactIsHash.hash.ioc_confidence,
                    artifact.artifactIsHash.hash.ioc_level
                ])
    return {
        "artifact": artifacts,
        "hashid": hashids,
        "infos": infos,
    }

### Attachments

def get_attachments(case_mail_attachments):
    """
    Retrieve attachments information from the given case mail attachments.

    Args:
        case_mail_attachments (list): A list of case mail attachments.

    Returns:
        dict: A dictionary containing the attachment information, hash IDs, and file information.

    """

    attachments = []
    rands = []
    infos = []

    for attachment in case_mail_attachments:
        if not attachment.file:
            continue
        file_info = {
            'file_score': attachment.file.file_score,
            'file_confidence': attachment.file.file_confidence,
            'file_level': attachment.file.file_level,
            'linked_hash_score': attachment.file.linked_hash.ioc_score,
            'linked_hash_confidence': attachment.file.linked_hash.ioc_confidence,
            'linked_hash_level': attachment.file.linked_hash.ioc_level,
        }

        attachments.append({
            'file_name': str(attachment.file.file_path.name),
            'linked_hash_value': attachment.file.linked_hash.value,
        })

        rands.append(get_rand(attachment.file.id))
        infos.append(file_info)
    
    # Log success message

    return {
        "attachment": attachments,
        "hashid": rands,
        "infos": infos,
    }

def generate_html(case):
    """Generate HTML for a given case.

    Args:
        case (Case): The case object.

    Returns:
        dict: A dictionary containing the HTML information.
    """
    case_file = case.fileOrMail.file if case.fileOrMail else None
    case_file_hash = case.fileOrMail.file.linked_hash if case_file else None
    case_hash = case.nonFileIocs.hash if case.nonFileIocs else None
    case_ip = case.nonFileIocs.ip if case.nonFileIocs else None
    case_url = case.nonFileIocs.url if case.nonFileIocs else None
    case_mail = case.fileOrMail.mail if case.fileOrMail else None
    case_mail_body = case.fileOrMail.mail.mail_body if case_mail else None
    case_mail_header = case.fileOrMail.mail.mail_header if case_mail else None
    case_mail_attachments = MailAttachment.objects.filter(mail=case.fileOrMail.mail) if case_mail else None
    case_mail_artifacts = MailArtifact.objects.filter(mail=case.fileOrMail.mail) if case_mail else None
    
    case_info = get_case_info(case)
    file_info = get_file_info(case_file)
    file_hash_info = get_file_hash_info(case_file_hash)
    hash_info = get_hash_info(case_hash)
    mail_info = get_mail_info(case_mail)
    mail_body_info = get_mail_body_info(case_mail_body)
    mail_header_info = get_mail_header_info(case_mail_header)
    ip_info = get_ip_info(case_ip)
    url_info = get_url_info(case_url)
    artifacts_info = get_artifacts_info(case_mail_artifacts)
    attachments_info = get_attachments_info(case_mail_attachments)
    analyzers_info = get_analyzers_info(case_file, case_file_hash, case_hash, case_ip, case_url, case_mail_body, case_mail_header, case_mail_attachments, case_mail_artifacts)
    html = {
        **case_info,
        **file_info,
        **file_hash_info,
        **hash_info,
        **mail_info,
        **mail_body_info,
        **mail_header_info,
        **ip_info,
        **url_info,
        **artifacts_info,
        **attachments_info,
        **analyzers_info,
    }
    
    return html

def get_case_info(case):
    """
    Returns a dictionary containing information about a case.

    Args:
        case (Case): The case object to retrieve information from.

    Returns:
        dict: A dictionary containing the following information:
            - case_id (int): The ID of the case.
            - user (str): The username of the reporter.
            - pub_date (str): The creation date of the case in the format "%d/%m/%Y %H:%M:%S".
            - status (str): The status of the case.
            - results (str): The results of the case.
            - case_score (float): The final score of the case.
            - confidence (float): The final confidence of the case.
            - challenge (bool): Indicates if the case is challenged.
            - analysis_done (bool): Indicates if the analysis is done.
    """
    return {
        "case_id": case.id,
        "user": case.reporter.username,
        "pub_date": case.creation_date.strftime("%d/%m/%Y %H:%M:%S"),
        "status": case.status,
        "results": case.results,
        "results_ai": case.resultsAI,
        "case_score": case.finalScore,
        "case_score_ai": case.scoreAI,
        "confidence": case.finalConfidence,
        "confidence_ai": case.confidenceAI,
        "category_ai": case.categoryAI,
        "challenge": case.is_challenged,
        "analysis_done": case.analysis_done,
    }

def get_file_info(case_file):
    """Returns a dictionary containing information about a file.

    Args:
        case_file (File): The file object to retrieve information from.

    Returns:
        dict: A dictionary containing the following information:
            - file (str): The value of the linked hash of the file.
            - file_info (str): The SCL information of the file.
            - file_name (str): The name of the file.
            - filetype (str): The type of the file.
    """
    if case_file:
        return {
            "file": case_file.linked_hash.value,
            "file_info": get_scl(case_file, "file"),
            "file_name": case_file.file_path.name,
            "filetype": case_file.filetype,
        }
    else :
        return {
            "file": None,
            "file_info": None,
            "file_name": None,
            "filetype": None,
        }

def get_file_hash_info(case_file_hash):
    """Returns a dictionary containing information about a file hash.

    Args:
        case_file_hash (FileHash): The file hash object to retrieve information from.

    Returns:
        dict: A dictionary containing the following information:
            - file_hash (str): The value of the file hash.
            - file_hash_info (str): The SCL information of the file hash.
    """
    if case_file_hash:
        return {
            "file_hash": case_file_hash.value,
            "file_hash_info": get_scl(case_file_hash, "hash"),
        }
    else:
        return {
            "file_hash": None,
            "file_hash_info": None,
        }

def get_hash_info(case_hash):
    """Returns a dictionary containing information about a hash.

    Args:
        case_hash (Hash): The hash object to retrieve information from.

    Returns:
        dict: A dictionary containing the following information:
            - hash (str): The value of the hash.
            - hash_info (str): The SCL information of the hash.
            - hash_type (str): The type of the hash.
    """
    if case_hash:
        return {
            "hash": case_hash.value,
            "hash_info": get_scl(case_hash, "hash"),
            "hash_type": case_hash.hashtype,
        }
    else:
        return {
            "hash": None,
            "hash_info": None,
            "hash_type": None,
        }

def get_mail_info(case_mail):
    """Returns a dictionary containing information about a mail.

    Args:
        case_mail (Mail): The mail object to retrieve information from.

    Returns:
        dict: A dictionary containing the following information:
            - mail (str): The subject of the mail.
    """
    if case_mail:
        return {
            "mail": case_mail.subject,
        }
    else:
        return {
            "mail": None,
        }

def get_mail_body_info(case_mail_body):
    """
    Get mail body information.

    Args:
        case_mail_body (MailBody): The mail body object.

    Returns:
        dict: A dictionary containing the mail body and its information.
            - mail_body (str): The fuzzy hash of the mail body.
            - mail_body_info (str): The information obtained from the mail body.
    """
    if case_mail_body:
        return {
            "mail_body": case_mail_body.fuzzy_hash,
            "mail_body_info": get_scl(case_mail_body, "body"),
        }
    else:
        return {
            "mail_body": None,
            "mail_body_info": None,
        }
        
def get_mail_header_info(case_mail_header):
    """Returns a dictionary containing information about a mail header.

    Args:
        case_mail_header (MailHeader): The mail header object to retrieve information from.

    Returns:
        dict: A dictionary containing the following information:
            - mail_header (str): The fuzzy hash of the mail header.
            - mail_header_info (str): The information obtained from the mail header.
    """
    if case_mail_header:
        return {
            "mail_header": case_mail_header.fuzzy_hash,
            "mail_header_info": get_scl(case_mail_header, "header"),
        }
    else:
        return {
            "mail_header": None,
            "mail_header_info": None,
        }
        
def get_ip_info(case_ip):
    """
    Get IP information for a given case IP.

    Args:
        case_ip (CaseIP): The case IP object.

    Returns:
        dict: A dictionary containing the IP and its information. The dictionary has the following keys:
            - 'ip': The IP address.
            - 'ip_info': The information associated with the IP.
    """
    if case_ip:
        return {
            "ip": case_ip.address,
            "ip_info": get_scl(case_ip, "ip"),
        }
    else:
        return {
            "ip": None,
            "ip_info": None,
        }
        
def get_url_info(case_url):
    """
    Get information about a case URL.

    Args:
        case_url (CaseURL): The case URL object.

    Returns:
        dict: A dictionary containing the following information:
            - 'url': The address of the case URL.
            - 'url_info': The information obtained from the case URL.
            - 'url_id': The ID of the case URL.
    """
    if case_url:
        return {
            "url": case_url.address,
            "url_info": get_scl(case_url, "url"),
            "url_id": case_url.id,
            "url_vt_id": url_id(case_url.address)
        }
    else:
        return {
            "url": None,
            "url_info": None,
            "url_id": None,
        }

def get_artifacts_info(case_mail_artifacts):
    """Returns a dictionary containing information about the artifacts of a mail.

    Args:
        case_mail_artifacts (MailArtifacts): The mail artifacts object to retrieve information from.

    Returns:
        dict: A dictionary containing the following information:
            - 'artifacts': The artifacts of the mail.
    """
    if case_mail_artifacts:
        return {
            "artifacts": get_artifacts(case_mail_artifacts),
        }
    else:
        return {
            "artifacts": None,
        }

def get_attachments_info(case_mail_attachments):
    """Get information about the attachments of a case mail.

    Args:
        case_mail_attachments (MailAttachments): The mail attachments object to retrieve information from.

    Returns:
        dict: A dictionary containing the following information:
            - 'attachments': The attachments of the mail.
    """
    if case_mail_attachments:
        return {
            "attachments": get_attachments(case_mail_attachments),
        }
    else:
        return {
            "attachments": None,
        }

def get_analyzers_info(case_file, case_file_hash, case_hash, case_ip, case_url, case_mail_body, case_mail_header, case_mail_attachments, case_mail_artifacts):
    """
    Get information about the analyzers associated with different case objects.

    Args:
        case_file (CaseFile): The case file object.
        case_file_hash (CaseFileHash): The case file hash object.
        case_hash (CaseHash): The case hash object.
        case_ip (CaseIP): The case IP object.
        case_url (CaseURL): The case URL object.
        case_mail_body (CaseMailBody): The case mail body object.
        case_mail_header (CaseMailHeader): The case mail header object.
        case_mail_attachments (CaseMailAttachments): The case mail attachments object.
        case_mail_artifacts (CaseMailArtifacts): The case mail artifacts object.

    Returns:
        dict: A dictionary containing information about the analyzers associated with different case objects.
            - 'analyzers': The IDs of all the analyzers associated with the case objects.
            - 'case_file_analyzers': The analyzers associated with the case file.
            - 'case_file_hash_analyzers': The analyzers associated with the case file hash.
            - 'case_hash_analyzers': The analyzers associated with the case hash.
            - 'case_ip_analyzers': The analyzers associated with the case IP.
            - 'case_url_analyzers': The analyzers associated with the case URL.
            - 'case_mail_body_analyzers': The analyzers associated with the case mail body.
            - 'case_mail_header_analyzers': The analyzers associated with the case mail header.
            - 'case_mail_attachments_analyzers': The analyzers associated with the case mail attachments.
            - 'case_mail_artifacts_analyzers': The analyzers associated with the case mail artifacts.
    """
    analyzers = []
    analyzers.extend(get_file_analyzers(case_file))
    analyzers.extend(get_file_hash_analyzers(case_file_hash))
    analyzers.extend(get_hash_analyzers(case_hash))
    analyzers.extend(get_ip_analyzers(case_ip))
    analyzers.extend(get_url_analyzers(case_url))
    analyzers.extend(get_mail_body_analyzers(case_mail_body))
    analyzers.extend(get_mail_header_analyzers(case_mail_header))
    analyzers.extend(get_mail_attachments_analyzers(case_mail_attachments))
    analyzers.extend(get_mail_artifacts_analyzers(case_mail_artifacts))
    
    analyzers_id = [analyzer["id"] for analyzer in analyzers]
    
    return {
        "analyzers": list(analyzers_id),
        "case_file_analyzers": get_file_analyzers(case_file),
        "case_file_hash_analyzers": get_file_hash_analyzers(case_file_hash),
        "case_hash_analyzers": get_hash_analyzers(case_hash),
        "case_ip_analyzers": get_ip_analyzers(case_ip),
        "case_url_analyzers": get_url_analyzers(case_url),
        "case_mail_body_analyzers": get_mail_body_analyzers(case_mail_body),
        "case_mail_header_analyzers": get_mail_header_analyzers(case_mail_header),
        "case_mail_attachments_analyzers": get_mail_attachments_analyzers(case_mail_attachments),
        "case_mail_artifacts_analyzers": get_mail_artifacts_analyzers(case_mail_artifacts),
    }

        
def get_file_analyzers(case_file):
    """
    Retrieve a list of file analyzers for a given case file.

    Args:
        case_file (File): The case file for which to retrieve the analyzers.

    Returns:
        list: A list of dictionaries containing information about each analyzer.
            Each dictionary contains the following keys:
            - "analyzer_name": The name of the analyzer.
            - "status": The status of the analyzer.
            - "score": The score assigned by the analyzer.
            - "confidence": The confidence level of the analyzer.
            - "level": The level of the analyzer.
            - "artifact": The file name.
    """
    analyzers = []
    unique_analyzers = set()  # Set to track unique analyzer names
    if case_file:
        file_analyzers = AnalyzerReport.objects.filter(file=case_file).order_by('-creation_date')
        for analyzer in file_analyzers:
            if analyzer.analyzer.name not in unique_analyzers:
                unique_analyzers.add(analyzer.analyzer.name)
                analyzers.append({
                    "id": analyzer.id,
                    "analyzer_name": analyzer.analyzer.name,
                    "status": analyzer.status,
                    "score": analyzer.score,
                    "confidence": analyzer.confidence,
                    "level": analyzer.level,
                    "artifact": case_file.file_path.name
                })
    return analyzers



def get_file_hash_analyzers(case_file_hash):
    """
    Retrieve a list of file hash analyzers for a given case file hash.

    Args:
        case_file_hash (Hash): The case file hash for which to retrieve the analyzers.

    Returns:
        list: A list of dictionaries containing information about each analyzer.
            Each dictionary contains the following keys:
            - "analyzer_name": The name of the analyzer.
            - "status": The status of the analyzer.
            - "score": The score assigned by the analyzer.
            - "confidence": The confidence level of the analyzer.
            - "level": The level of the analyzer.
            - "artifact": The hash value.
    """
    analyzers = []
    unique_analyzers = set()  # Set to track unique analyzer names
    if case_file_hash:
        file_hash_analyzers = AnalyzerReport.objects.filter(hash=case_file_hash).order_by('-creation_date')
        for analyzer in file_hash_analyzers:
            if analyzer.analyzer.name not in unique_analyzers:
                unique_analyzers.add(analyzer.analyzer.name)
                analyzers.append({
                    "id": analyzer.id,
                    "analyzer_name": analyzer.analyzer.name,
                    "status": analyzer.status,
                    "score": analyzer.score,
                    "confidence": analyzer.confidence,
                    "level": analyzer.level,
                    "artifact": case_file_hash.value
                })
    return analyzers

def get_hash_analyzers(case_hash):
    """
    Retrieve a list of hash analyzers for a given case hash.

    Args:
        case_hash (Hash): The case hash to retrieve analyzers for.

    Returns:
        list: A list of dictionaries containing information about each analyzer.
            Each dictionary contains the following keys:
            - "analyzer_name" (str): The name of the analyzer.
            - "status" (str): The status of the analyzer.
            - "score" (float): The score assigned by the analyzer.
            - "confidence" (float): The confidence level of the analyzer.
            - "level" (str): The level of the analyzer.
            - "artifact": The hash value.
    """
    analyzers = []
    unique_analyzers = set()  # Set to track unique analyzer names
    if case_hash:
        hash_analyzers = AnalyzerReport.objects.filter(hash=case_hash).order_by('-creation_date')
        for analyzer in hash_analyzers:
            if analyzer.analyzer.name not in unique_analyzers:
                unique_analyzers.add(analyzer.analyzer.name)
                analyzers.append({
                    "id": analyzer.id,
                    "analyzer_name": analyzer.analyzer.name,
                    "status": analyzer.status,
                    "score": analyzer.score,
                    "confidence": analyzer.confidence,
                    "level": analyzer.level,
                    "artifact": case_hash.value
                })
    return analyzers


def get_ip_analyzers(case_ip):
    """
    Retrieve a list of IP analyzers for a given case IP.

    Args:
        case_ip (CaseIP): The case IP object.

    Returns:
        list: A list of dictionaries containing information about each IP analyzer.
            Each dictionary contains the following keys:
            - "analyzer_name": The name of the analyzer.
            - "status": The status of the analyzer.
            - "score": The score assigned by the analyzer.
            - "confidence": The confidence level of the analyzer.
            - "level": The level of the analyzer.
            - "artifact": The IP address.
    """
    analyzers = []
    unique_analyzers = set()  # Set to track unique analyzer names
    if case_ip:
        ip_analyzers = AnalyzerReport.objects.filter(ip=case_ip).order_by('-creation_date')
        for analyzer in ip_analyzers:
            if analyzer.analyzer.name not in unique_analyzers:
                unique_analyzers.add(analyzer.analyzer.name)
                analyzers.append({
                    "id": analyzer.id,
                    "analyzer_name": analyzer.analyzer.name,
                    "status": analyzer.status,
                    "score": analyzer.score,
                    "confidence": analyzer.confidence,
                    "level": analyzer.level,
                    "artifact": case_ip.address
                })
    return analyzers

def get_url_analyzers(case_url):
    """
    Retrieve a list of URL analyzers for a given case URL.

    Args:
        case_url (CaseURL): The case URL object.

    Returns:
        list: A list of dictionaries containing information about each URL analyzer.
            Each dictionary has the following keys:
            - "analyzer_name" (str): The name of the analyzer.
            - "status" (str): The status of the analyzer.
            - "score" (float): The score assigned by the analyzer.
            - "confidence" (float): The confidence level of the analyzer.
            - "level" (str): The level of the analyzer.
            - "artifact": The URL address.
    """
    analyzers = []
    unique_analyzers = set()  # Set to track unique analyzer names
    if case_url:
        url_analyzers = AnalyzerReport.objects.filter(url=case_url).order_by('-creation_date')
        for analyzer in url_analyzers:
            if analyzer.analyzer.name not in unique_analyzers:
                unique_analyzers.add(analyzer.analyzer.name)
                analyzers.append({
                    "id": analyzer.id,
                    "analyzer_name": analyzer.analyzer.name,
                    "status": analyzer.status,
                    "score": analyzer.score,
                    "confidence": analyzer.confidence,
                    "level": analyzer.level,
                    "artifact": case_url.address
                })
    return analyzers

def get_mail_body_analyzers(case_mail_body):
    """
    Retrieve a list of analyzer reports associated with a given case mail body.

    Args:
        case_mail_body (MailBody): The mail body of the case.

    Returns:
        list: A list of dictionaries containing information about each analyzer report.
            Each dictionary contains the following keys:
            - "analyzer_name": The name of the analyzer.
            - "status": The status of the analyzer report.
            - "score": The score assigned by the analyzer.
            - "confidence": The confidence level of the analyzer.
            - "level": The severity level of the analyzer report.
            - "artifact": The mail body fuzzy hash.
    """
    analyzers = []
    unique_analyzers = set()  # Set to track unique analyzer names
    if case_mail_body:
        # Get analyzer reports for the mail body, ordered by the latest first
        mail_body_analyzers = AnalyzerReport.objects.filter(mail_body=case_mail_body).order_by('-creation_date')
        for analyzer in mail_body_analyzers:
            if analyzer.analyzer.name not in unique_analyzers:
                unique_analyzers.add(analyzer.analyzer.name)
                analyzers.append({
                    "id": analyzer.id,
                    "analyzer_name": analyzer.analyzer.name,
                    "status": analyzer.status,
                    "score": analyzer.score,
                    "confidence": analyzer.confidence,
                    "level": analyzer.level,
                    "artifact": case_mail_body.fuzzy_hash
                })
    return analyzers

def get_mail_header_analyzers(case_mail_header):
    """
    Retrieve a list of analyzer reports for a given mail header.

    Args:
        case_mail_header (MailHeader): The mail header object.

    Returns:
        list: A list of dictionaries containing information about each analyzer report.
            Each dictionary contains the following keys:
            - "analyzer_name": The name of the analyzer.
            - "status": The status of the analyzer report.
            - "score": The score assigned by the analyzer.
            - "confidence": The confidence level of the analyzer report.
            - "level": The level of the analyzer report.
            - "artifact": The mail header fuzzy hash.
    """
    analyzers = []
    unique_analyzers = set()  # Set to track unique analyzer names
    if case_mail_header:
        mail_header_analyzers = AnalyzerReport.objects.filter(mail_header=case_mail_header).order_by('-creation_date')
        for analyzer in mail_header_analyzers:
            if analyzer.analyzer.name not in unique_analyzers:
                unique_analyzers.add(analyzer.analyzer.name)
                analyzers.append({
                    "id": analyzer.id,
                    "analyzer_name": analyzer.analyzer.name,
                    "status": analyzer.status,
                    "score": analyzer.score,
                    "confidence": analyzer.confidence,
                    "level": analyzer.level,
                    "artifact": case_mail_header.fuzzy_hash
                })
    return analyzers

def get_mail_attachments_analyzers(case_mail_attachments):
    """Get analyzers for mail attachments.

    This function takes a list of mail attachments and returns a list of analyzers for those attachments.

    Args:
        case_mail_attachments (list): A list of mail attachments.

    Returns:
        list: A list of analyzers for the mail attachments.
    """
    analyzers = []
    if case_mail_attachments:
        for attachment in case_mail_attachments:
            analyzers += get_attachment_file_analyzers(attachment)
            analyzers += get_attachment_hash_analyzers(attachment)
    return analyzers

def get_attachment_file_analyzers(attachment):
    """
    Retrieve a list of analyzers for a given attachment file.

    Args:
        attachment (Attachment): The attachment object.

    Returns:
        list: A list of dictionaries containing information about each analyzer.
            Each dictionary has the following keys:
            - 'file_path': The file path of the attachment.
            - 'analyzer_name': The name of the analyzer.
            - 'status': The status of the analyzer.
            - 'score': The score assigned by the analyzer.
            - 'confidence': The confidence level of the analyzer.
            - 'level': The level of the analyzer.
            - 'artifact': The file name.
    """
    analyzers = []
    unique_analyzers = set()  # Set to track unique analyzer names
    if not attachment.file:
        return analyzers
    mail_attachments_analyzers = AnalyzerReport.objects.filter(file=attachment.file).order_by('-creation_date')
    
    for analyzer in mail_attachments_analyzers:
        if analyzer.analyzer.name not in unique_analyzers:  # Ensure only one report per analyzer
            unique_analyzers.add(analyzer.analyzer.name)
            analyzers.append({
                "id": analyzer.id,
                "analyzer_name": analyzer.analyzer.name,
                "status": analyzer.status,
                "score": analyzer.score,
                "confidence": analyzer.confidence,
                "level": analyzer.level,
                "artifact": attachment.file.file_path.name
            })
    
    return analyzers

def get_attachment_hash_analyzers(attachment):
    """
    Retrieve a list of analyzers associated with the given attachment's hash.

    Args:
        attachment (Attachment): The attachment object.

    Returns:
        list: A list of dictionaries containing information about each analyzer.
            Each dictionary has the following keys:
            - analyzer_name (str): The name of the analyzer.
            - status (str): The status of the analyzer.
            - score (float): The score assigned by the analyzer.
            - confidence (float): The confidence level of the analyzer.
            - level (str): The level of the analyzer.
            - artifact: The linked hash value.
    """
    analyzers = []
    unique_analyzers = set()  # Set to track unique analyzer names
    if not attachment.file or not attachment.file.linked_hash:
        return analyzers
    mail_hash_attachments_analyzers = AnalyzerReport.objects.filter(hash=attachment.file.linked_hash).order_by('-creation_date')
    
    for analyzer in mail_hash_attachments_analyzers:
        if analyzer.analyzer.name not in unique_analyzers:  # Ensure only one report per analyzer
            unique_analyzers.add(analyzer.analyzer.name)
            analyzers.append({
                "id": analyzer.id,
                "analyzer_name": analyzer.analyzer.name,
                "status": analyzer.status,
                "score": analyzer.score,
                "confidence": analyzer.confidence,
                "level": analyzer.level,
                "artifact": attachment.file.linked_hash.value
            })
    return analyzers

def get_mail_artifacts_analyzers(case_mail_artifacts):
    """
    Returns a list of analyzers based on the given mail artifacts.

    Args:
        case_mail_artifacts (list): A list of mail artifacts.

    Returns:
        list: A list of analyzers.
    """
    analyzers = []
    if case_mail_artifacts:
        for artifact in case_mail_artifacts:
            if artifact.artifact_type == 'IP':
                analyzers += get_artifact_ip_analyzers(artifact)
            elif artifact.artifact_type == 'URL':
                analyzers += get_artifact_url_analyzers(artifact)
            elif artifact.artifact_type == 'Hash':
                analyzers += get_artifact_hash_analyzers(artifact)
    return analyzers

def get_artifact_ip_analyzers(artifact):
    """
    Retrieve a list of analyzers for a given artifact IP.

    Args:
        artifact (Artifact): The artifact object representing the IP.

    Returns:
        list: A list of dictionaries containing information about the analyzers.
            Each dictionary contains the following keys:
            - analyzer_name (str): The name of the analyzer.
            - status (str): The status of the analyzer.
            - score (float): The score assigned by the analyzer.
            - confidence (float): The confidence level of the analyzer.
            - level (str): The level of the analyzer.
            - artifact: The IP address.
    """
    analyzers = []
    unique_analyzers = set()  # Set to track unique analyzer names
    if artifact.artifactIsIp:
        ip_analyzers = AnalyzerReport.objects.filter(ip=artifact.artifactIsIp.ip).order_by('-creation_date')
        for analyzer in ip_analyzers:
            if analyzer.analyzer.name not in unique_analyzers:
                unique_analyzers.add(analyzer.analyzer.name)
                analyzers.append({
                    "id": analyzer.id,
                    "analyzer_name": analyzer.analyzer.name,
                    "status": analyzer.status,
                    "score": analyzer.score,
                    "confidence": analyzer.confidence,
                    "level": analyzer.level,
                    "artifact": artifact.artifactIsIp.ip.address
                })
    return analyzers

def get_artifact_url_analyzers(artifact):
    """
    Retrieve a list of analyzers for a given artifact URL.

    Args:
        artifact (Artifact): The artifact object representing the URL.

    Returns:
        list: A list of dictionaries containing information about each analyzer.
            Each dictionary has the following keys:
            - analyzer_name (str): The name of the analyzer.
            - status (str): The status of the analyzer.
            - score (float): The score assigned by the analyzer.
            - confidence (float): The confidence level of the analyzer.
            - level (str): The level of the analyzer.
            - artifact: The URL address.
    """
    analyzers = []
    unique_analyzers = set()  # Set to track unique analyzer names
    if artifact.artifactIsUrl:
        mail_artifacts_analyzers = AnalyzerReport.objects.filter(url=artifact.artifactIsUrl.url).order_by('-creation_date')

        for analyzer in mail_artifacts_analyzers:
            if analyzer.analyzer.name not in unique_analyzers:  # Ensure only one report per analyzer
                unique_analyzers.add(analyzer.analyzer.name)
                analyzers.append({
                    "id": analyzer.id,
                    "analyzer_name": analyzer.analyzer.name,
                    "status": analyzer.status,
                    "score": analyzer.score,
                    "confidence": analyzer.confidence,
                    "level": analyzer.level,
                    "artifact": artifact.artifactIsUrl.url.address
                })
    
    return analyzers

def get_artifact_hash_analyzers(artifact):
    """
    Retrieves a list of analyzers associated with a given artifact hash.

    Args:
        artifact (Artifact): The artifact object containing the hash.

    Returns:
        list: A list of dictionaries, each representing an analyzer associated with the artifact hash.
            Each dictionary contains the following information:
            - analyzer_name (str): The name of the analyzer.
            - status (str): The status of the analyzer.
            - score (float): The score assigned by the analyzer.
            - confidence (float): The confidence level of the analyzer.
            - level (str): The level of the analyzer.
            - artifact: The hash value.
    """
    analyzers = []
    unique_analyzers = set()  # Set to track unique analyzer names
    if artifact.artifactIsHash:
        mail_artifacts_analyzers = AnalyzerReport.objects.filter(hash=artifact.artifactIsHash.hash).order_by('-creation_date')

        for analyzer in mail_artifacts_analyzers:
            if analyzer.analyzer.name not in unique_analyzers:  # Ensure only one report per analyzer
                unique_analyzers.add(analyzer.analyzer.name)
                analyzers.append({
                    "id": analyzer.id,
                    "analyzer_name": analyzer.analyzer.name,
                    "status": analyzer.status,
                    "score": analyzer.score,
                    "confidence": analyzer.confidence,
                    "level": analyzer.level,
                    "artifact": artifact.artifactIsHash.hash.value
                })
    
    return analyzers
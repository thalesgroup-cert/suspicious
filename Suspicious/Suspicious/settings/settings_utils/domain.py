import csv
import json
import re
from domain_process.models import Domain
from settings.models import AllowListDomain, DenyListDomain, CampaignDomainAllowList
from domain_process.domain_utils.domain_handler import DomainHandler

CSV_CONTENT_TYPE = 'text/csv'
JSON_CONTENT_TYPE = 'application/json'
TXT_CONTENT_TYPE = 'text/plain'
INVALID_FILETYPE_ERROR = 'Invalid file type.'

def handle_domain_file(file):
    """Handles the domain file based on its content type.

    Args:
        file (File): The domain file to be handled.

    Raises:
        ValueError: If the content type of the file is invalid.

    Returns:
        Result: The result of handling the domain file.
    """
    if file.content_type == CSV_CONTENT_TYPE:
        return handle_domain_csv_file(file)
    elif file.content_type == JSON_CONTENT_TYPE:
        return handle_domain_json_file(file)
    elif file.content_type == TXT_CONTENT_TYPE:
        return handle_domain_txt_file(file)
    else:
        raise ValueError(INVALID_FILETYPE_ERROR)

def handle_bdomain_file(file):
    """Handles the domain file based on its content type.

    Args:
        file (File): The domain file to be handled.

    Raises:
        ValueError: If the content type of the file is invalid.

    Returns:
        Result: The result of handling the domain file.
    """
    if file.content_type == CSV_CONTENT_TYPE:
        return handle_bdomain_csv_file(file)
    elif file.content_type == JSON_CONTENT_TYPE:
        return handle_bdomain_json_file(file)
    elif file.content_type == TXT_CONTENT_TYPE:
        return handle_bdomain_txt_file(file)
    else:
        raise ValueError(INVALID_FILETYPE_ERROR)

def handle_campaign_domain_file(file):
    """Handles the campaign domain file based on its content type.

    Args:
        file (File): The campaign domain file to be handled.

    Raises:
        ValueError: If the content type of the file is invalid.

    Returns:
        Result: The result of handling the campaign domain file.
    """
    if file.content_type == CSV_CONTENT_TYPE:
        return handle_campaign_domain_csv_file(file)
    elif file.content_type == JSON_CONTENT_TYPE:
        return handle_campaign_domain_json_file(file)
    elif file.content_type == TXT_CONTENT_TYPE:
        return handle_campaign_domain_txt_file(file)
    else:
        raise ValueError(INVALID_FILETYPE_ERROR)

def process_domains(domains, user):
    """Process a list of domains and associate them with a user.

    This function takes a list of domains and a user as input. It iterates over each domain in the list,
    converts it to lowercase, and checks if it is a valid domain using the Validator class. If the domain
    is valid and not already present in the AllowListDomain table, it creates a new entry in the Domain
    table and associates it with the user in the AllowListDomain table. The function returns two lists:
    good_domains, which contains the domains that were successfully processed, and error_domains, which
    contains the domains that encountered an error during processing.

    Args:
        domains (list): A list of domains to process.
        user (User): The user to associate the domains with.

    Returns:
        tuple: A tuple containing two lists - good_domains and error_domains.
    """
    good_domains = []
    error_domains = []
    for domain in domains:
        domain = domain.lower()

        if DomainHandler().validate_domain(domain) == "Domain":
            try:
                domain_db = Domain.objects.get(value=domain)
            except Domain.DoesNotExist:
                domain_db = Domain.objects.create(value=domain)

            if domain_db and not AllowListDomain.objects.filter(domain=domain_db).exists():
                AllowListDomain.objects.create(domain=domain_db, user=user)
                good_domains.append(domain)
            else:
                error_domains.append(domain)

    return good_domains, error_domains

def process_bdomains(domains, user):
    """Process a list of domains and associate them with a user.

    This function takes a list of domains and a user as input. It iterates over each domain in the list,
    converts it to lowercase, and checks if it is a valid domain using the Validator class. If the domain
    is valid and not already present in the DenyListDomain table, it creates a new entry in the Domain
    table and associates it with the user in the DenyListDomain table. The function returns two lists:
    good_domains, which contains the domains that were successfully processed, and error_domains, which
    contains the domains that encountered an error during processing.

    Args:
        domains (list): A list of domains to process.
        user (User): The user to associate the domains with.

    Returns:
        tuple: A tuple containing two lists - good_domains and error_domains.
    """
    good_domains = []
    error_domains = []
    for domain in domains:
        domain = domain.lower()

        if DomainHandler().validate_domain(domain) == "Domain":
            try:
                domain_db = Domain.objects.get(value=domain)
            except Domain.DoesNotExist:
                domain_db = Domain.objects.create(value=domain)

            if domain_db and not DenyListDomain.objects.filter(domain=domain_db).exists():
                DenyListDomain.objects.create(domain=domain_db, user=user)
                good_domains.append(domain)
            else:
                error_domains.append(domain)

    return good_domains, error_domains

def process_campaign_domains(domains, user):
    """Process a list of campaign domains and associate them with a user.

    This function takes a list of domains and a user as input. It iterates over each domain in the list,
    converts it to lowercase, and checks if it is a valid domain using the Validator class. If the domain
    is valid and not already present in the CampaignDomainAllowList table, it creates a new entry in the Domain
    table and associates it with the user in the CampaignDomainAllowList table. The function returns two lists:
    good_domains, which contains the domains that were successfully processed, and error_domains, which
    contains the domains that encountered an error during processing.

    Args:
        domains (list): A list of domains to process.
        user (User): The user to associate the domains with.

    Returns:
        tuple: A tuple containing two lists - good_domains and error_domains.
    """
    good_domains = []
    error_domains = []
    for domain in domains:
        domain = domain.lower()

        if DomainHandler().validate_domain(domain) == "Domain":
            try:
                domain_db = Domain.objects.get(value=domain)
            except Domain.DoesNotExist:
                domain_db = Domain.objects.create(value=domain)

            if domain_db and not CampaignDomainAllowList.objects.filter(domain=domain_db).exists():
                CampaignDomainAllowList.objects.create(domain=domain_db, user=user)
                good_domains.append(domain)
            else:
                error_domains.append(domain)

    return good_domains, error_domains

def generate_message_domain(user, good_domains, error_domains, count):
    """
    Generate a message based on the user, good domains, error domains, and count.

    Args:
        user (str): The user for whom the message is generated.
        good_domains (list): A list of good domains added to the database.
        error_domains (list): A list of error domains that were not added to the database.
        count (int): The number of domains already in the database.

    Returns:
        str: The generated message.
    """
    message = f'User : {user} - {len(good_domains)} domains added to the database. {count} domains already in the database.'
    if error_domains:
        message += f' {len(error_domains)} domains not added to the database: {", ".join(error_domains)}.'
    return message


def preprocess_domains(domains):
    """Preprocesses a list of domains.

    This function removes empty lines and splits lines with multiple operators.

    Args:
        domains (list): A list of domains.

    Returns:
        list: A list of preprocessed domains.
    """
    processed = []
    for domain in domains:
        if isinstance(domain, str):
            split_domains = re.split(r'[ ,;\n]+', domain)
            processed.extend(d.strip() for d in split_domains if d.strip())
        elif isinstance(domain, dict):
            split_domains = re.split(r'[ ,;\n]+', domain["domain__value"])
            processed.extend(d.strip() for d in split_domains if d.strip())
        else:
            print(f"Warning: Skipping non-string item {domain}")
    return processed

def handle_domain_csv_file(file):
    """Reads and processes a CSV file containing domain data.

    Args:
        file (file-like object): The CSV file to be processed.

    Returns:
        list: A list of dictionaries representing each row in the CSV file.
    """
    reader = csv.DictReader(file.read().decode('utf-8').splitlines())
    return [row for row in reader]

def handle_domain_json_file(file):
    """Reads a JSON file and returns a list of domain names.

    Args:
        file (file-like object): The JSON file to be read.

    Returns:
        list: A list of domain names extracted from the JSON file.
    """
    data = json.loads(file.read().decode('utf-8'))
    return [item['domain'] for item in data]

def handle_domain_txt_file(file):
    """
    This function handles a domain text file.

    Args:
        file (file): The domain text file to be processed.

    Returns:
        list: A list of strings, where each string represents a line from the file.
    """
    return [line.decode('utf-8').strip() for line in file]

def handle_bdomain_csv_file(file):
    """Reads and processes a CSV file containing domain data.

    Args:
        file (file-like object): The CSV file to be processed.

    Returns:
        list: A list of dictionaries representing each row in the CSV file.
    """
    reader = csv.DictReader(file.read().decode('utf-8').splitlines())
    return [row for row in reader]

def handle_bdomain_json_file(file):
    """Reads a JSON file and returns a list of domain names.

    Args:
        file (file-like object): The JSON file to be read.

    Returns:
        list: A list of domain names extracted from the JSON file.
    """
    data = json.loads(file.read().decode('utf-8'))
    return [item['domain'] for item in data]

def handle_bdomain_txt_file(file):
    """
    This function handles a domain text file.

    Args:
        file (file): The domain text file to be processed.

    Returns:
        list: A list of strings, where each string represents a line from the file.
    """
    return [line.decode('utf-8').strip() for line in file]

def handle_campaign_domain_csv_file(file):
    """Reads and processes a CSV file containing campaign domain data.

    Args:
        file (file-like object): The CSV file to be processed.

    Returns:
        list: A list of dictionaries representing each row in the CSV file.
    """
    reader = csv.DictReader(file.read().decode('utf-8').splitlines())
    return [row for row in reader]

def handle_campaign_domain_json_file(file):
    """Reads a JSON file and returns a list of campaign domain names.

    Args:
        file (file-like object): The JSON file to be read.

    Returns:
        list: A list of campaign domain names extracted from the JSON file.
    """
    data = json.loads(file.read().decode('utf-8'))
    return [item['domain'] for item in data]

def handle_campaign_domain_txt_file(file):
    """
    This function handles a campaign domain text file.

    Args:
        file (file): The campaign domain text file to be processed.

    Returns:
        list: A list of strings, where each string represents a line from the file.
    """
    return [line.decode('utf-8').strip() for line in file]
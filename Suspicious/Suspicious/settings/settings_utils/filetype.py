import csv
import re
import json
from settings.models import AllowListFiletype

FILETYPE_PATTERNS = {
    "Filetype": r'^[a-zA-Z0-9]{1,10}$'
}

def validate_value(value, patterns):
    """Validate value using patterns and return the matched type"""
    for value_type, pattern in patterns.items():
        if re.fullmatch(pattern, value):
            return value_type
    return None

def validate_filetype(filetype):
    """Validate filetype value and return filetype type"""
    return validate_value(filetype, FILETYPE_PATTERNS)

def process_filetypes(filetypes, user):
    """Process a list of filetypes and filter out the allow_listed ones.

    Args:
        filetypes (list): A list of filetypes to process.
        user (User): The user object associated with the filetypes.

    Returns:
        tuple: A tuple containing two lists - the list of good filetypes (not in the allow_list) and the list of error filetypes (already in the allow_list).
    """
    good_filetypes = []
    error_filetypes = []
    for filetype in filetypes:
        filetype = filetype.lower()

        if validate_filetype(filetype) is not None:
            if not AllowListFiletype.objects.filter(filetype=filetype).exists():
                AllowListFiletype.objects.create(filetype=filetype, user=user)
                good_filetypes.append(filetype)
            else:
                error_filetypes.append(filetype)

    return good_filetypes, error_filetypes

def generate_filetype_message(good_filetypes, error_filetypes, count):
    """Generates a message based on the filetypes added to the database.

    Args:
        good_filetypes (list): A list of filetypes that were successfully added to the database.
        error_filetypes (list): A list of filetypes that were not added to the database.
        count (int): The number of filetypes already present in the database.

    Returns:
        str: A message summarizing the number of filetypes added and any errors encountered.
    """
    message = f'{len(good_filetypes)} filetypes added to the database. {count} filetypes already in the database.'
    if error_filetypes:
        message += f' {len(error_filetypes)} filetypes not added to the database: {", ".join(error_filetypes)}.'
    return message

def handle_filetype_csv_file(file):
    """Handle CSV file.

    This function takes a file object representing a CSV file and reads its contents.
    It returns a list containing the values from the first column of each row in the CSV file.

    Args:
        file (file-like object): The file object representing the CSV file.

    Returns:
        list: A list containing the values from the first column of each row in the CSV file.
    """
    reader = csv.reader(file.read().decode('utf-8').splitlines())
    return [row[0] for row in reader]

def handle_filetype_json_file(file):
    """Handle JSON file and extract filetypes.

    This function takes a JSON file object, reads its contents, and extracts the filetypes from the data.

    Args:
        file (file-like object): The JSON file object to be processed.

    Returns:
        list: A list of filetypes extracted from the JSON data.
    """
    data = json.loads(file.read().decode('utf-8'))
    return [item['filetype'] for item in data]

def handle_filetype_txt_file(file):
    """Handle a text file.

    This function takes a file object as input and returns a list of strings,
    where each string represents a line in the file.

    Args:
        file (file-like object): The text file to be processed.

    Returns:
        list: A list of strings, where each string represents a line in the file.
    """
    return [line.decode('utf-8').strip() for line in file]
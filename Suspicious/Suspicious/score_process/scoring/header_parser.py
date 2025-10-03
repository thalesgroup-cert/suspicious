import re
import ast
from email.parser import Parser
import logging

# Initialize the logger
update_cases_logger = logging.getLogger('tasp.cron.update_ongoing_case_jobs')

def extract_email_address(header_value):
    """
    Extract email address from a header field in the format 'Name <email@example.com>'.
    If no angle brackets are found, return the entire value.
    """
    match = re.search(r'<([^>]+)>', header_value)
    if match:
        return match.group(1)  # Extract the email part inside the angle brackets
    return header_value  # Return the full value if no brackets found

def extract_display_name(header_value):
    """
    Extract display name from a header field in the format 'Name <email@example.com>'.
    If no angle brackets are found, return None.
    """
    match = re.search(r'^(.*)<[^>]+>', header_value)
    if match:
        return match.group(1).strip()  # Extract the display name before the angle brackets
    return None  # Return None if no display name is found

def parse_email_headers(header_value):
    """
    Parse email headers from different formats (list of tuples, string, or dictionary) into a dictionary
    with case-insensitive keys, ensuring all required fields are returned.

    Args:
        header_value (Union[str, list, dict]): The raw headers.

    Returns:
        dict: A dictionary containing all parsed header key-value pairs, keys are lowercase.
    """
    update_cases_logger.debug(f"Starting to parse email headers: {header_value}")
    print(f"DEBUG: Starting to parse email headers: {header_value}")

    parsed_headers = {}

    # If the headers are a list of tuples, convert to dictionary
    if isinstance(header_value, list):
        for key, value in header_value:
            key_lower = key.lower()
            if key_lower in parsed_headers:
                if isinstance(parsed_headers[key_lower], list):
                    parsed_headers[key_lower].append(value)
                else:
                    parsed_headers[key_lower] = [parsed_headers[key_lower], value]
            else:
                parsed_headers[key_lower] = value

    # If the headers are a string, parse them using ast.literal_eval or treat as raw headers
    elif isinstance(header_value, str):
        try:
            evaluated_headers = ast.literal_eval(header_value)
            if isinstance(evaluated_headers, dict):
                parsed_headers = {k.lower(): v for k, v in evaluated_headers.items()}
                update_cases_logger.debug(f"Parsed headers from string evaluated as dictionary: {parsed_headers}")
                print(f"DEBUG: Parsed headers from string evaluated as dictionary: {parsed_headers}")
            else:
                update_cases_logger.warning(f"Evaluated string is not a dictionary: {evaluated_headers}")
        except (SyntaxError, ValueError) as e:
            update_cases_logger.warning(f"Failed to evaluate string as dictionary: {str(e)}. Treating it as raw headers.")
            parser = Parser()
            raw_headers = parser.parsestr(header_value)
            parsed_headers = {k.lower(): v for k, v in raw_headers.items()}
            update_cases_logger.debug(f"Parsed headers from raw string: {parsed_headers}")
            print(f"DEBUG: Parsed headers from raw string: {parsed_headers}")

    # If it's already a dictionary, just use the dictionary as is, normalize keys
    elif isinstance(header_value, dict):
        parsed_headers = {k.lower(): v for k, v in header_value.items()}
        update_cases_logger.debug(f"Parsed headers from dictionary: {parsed_headers}")

    else:
        raise ValueError(f"Unsupported header format: {type(header_value)}")

    # Now extract the required fields, using None if not found
    parsed_result = {
        'from': extract_email_address(parsed_headers.get('from', '')),
        'from_display_name': extract_display_name(parsed_headers.get('from', '')),
        'to': extract_email_address(parsed_headers.get('to', '')),
        'to_display_name': extract_display_name(parsed_headers.get('to', '')),
        'cc': extract_email_address(parsed_headers.get('cc', '')),
        'subject': parsed_headers.get('subject'),
        'reply_to': extract_email_address(parsed_headers.get('reply-to', '')),
        'return_path': parsed_headers.get('return-path'),
        'user_agent': parsed_headers.get('user-agent'),
        'send_date': parsed_headers.get('date')
    }

    update_cases_logger.debug(f"Finished parsing headers: {parsed_result}")
    print(f"DEBUG: Finished parsing headers: {parsed_result}")

    return parsed_result

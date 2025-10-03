import csv
import json
import os
import ldap
from django.contrib.auth.models import User
from profiles.models import CISOProfile
from profiles.profiles_utils.ldap import Ldap
import logging
import json
from pathlib import Path

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

ldap_config = config.get("ldap", {})
logger = logging.getLogger(__name__)


def process_cisos(cisos):
    """Process a list of CISOs.

    This function takes a list of CISOs (Chief Information Security Officers) and performs the following actions:
    - Checks if each CISO exists as a user in the User model.
    - If the CISO does not exist, it logs a warning and adds it to the error_cisos list.
    - If the CISO exists, it checks if a CISOProfile already exists for the user.
    - If a CISOProfile does not exist, it searches for the user's information in an LDAP server and creates a new CISOProfile.
    - If a CISOProfile already exists, it logs a warning and adds the CISO to the error_cisos list.

    Args:
        cisos (list): A list of CISOs.

    Returns:
        tuple: A tuple containing two lists:
            - good_cisos: A list of CISOs for which CISOProfiles were successfully created.
            - error_cisos: A list of CISOs for which errors occurred during processing.
    """
    good_cisos = []
    error_cisos = []
    ldap_server = Ldap().initialize_ldap()
    for ciso in cisos:
        ciso = ciso.lower()
        try:
            ciso_user = User.objects.get(username=ciso)
            logger.info(f"Username {ciso} found")
            if not CISOProfile.objects.filter(user=ciso_user).exists():
                logger.info(f"Creating CISO profile for user {ciso_user}")
                search_results = search_ldap_server(ldap_server, ciso)
                if search_results:
                    title = search_results[0][1]["title"][0].decode("utf-8")
                    business_category = search_results[0][1]["businessCategory"][
                        0
                    ].decode("utf-8")
                    CISOProfile.objects.create(
                        user=ciso_user, title=title, business_category=business_category
                    )
                    good_cisos.append(ciso)
                good_cisos.append(ciso)
            else:
                logger.warning(f"CISO profile for user {ciso_user} already exists")
                error_cisos.append(ciso)
        except User.DoesNotExist:
            logger.warning(f"Username {ciso} not found")
            error_cisos.append(ciso)

    ldap_server.unbind_s()
    return good_cisos, error_cisos


def generate_message(good_cisos, error_cisos, count):
    """Generate a message based on the CISO profiles added to the database.

    This function takes in three parameters: `good_cisos`, `error_cisos`, and `count`.
    It generates a message based on the number of CISO profiles added to the database and the number of profiles already in the database.

    Args:
        good_cisos (list): A list of CISO profiles that were successfully added to the database.
        error_cisos (list): A list of CISO profiles that were not added to the database.
        count (int): The number of CISO profiles already in the database.

    Returns:
        str: A message summarizing the number of CISO profiles added and any errors encountered.
    """
    message = f"{len(good_cisos)} CISO profiles added to the database. {count} CISO profiles already in the database."
    if error_cisos:
        message += f' {len(error_cisos)} CISO profiles not added to the database: {", ".join(error_cisos)}.'
    return message


def handle_csv_file(file):
    """
    Process a CSV file and return its contents as a list of dictionaries.

    Args:
        file (file-like object): The CSV file to be processed.

    Returns:
        list: A list of dictionaries representing the rows in the CSV file.
    """
    reader = csv.DictReader(file.read().decode("utf-8").splitlines())
    return [row for row in reader]


def handle_json_file(file):
    """
    Read and process a JSON file.

    Args:
        file (file-like object): The JSON file to be processed.

    Returns:
        list: A list of 'ciso' values extracted from the JSON data.
    """
    data = json.loads(file.read().decode("utf-8"))
    return [item["ciso"] for item in data]


def handle_txt_file(file):
    """Handles a text file.

    This function takes a file object as input and reads its contents line by line.
    Each line is decoded using UTF-8 encoding and stripped of leading and trailing whitespace.

    Args:
        file (file-like object): The text file to be processed.

    Returns:
        list: A list of strings, where each string represents a line from the text file.
    """
    return [line.decode("utf-8").strip() for line in file]


def search_ldap_server(ldap_server, ciso):
    """
    Search the LDAP server for a given CISO.

    Args:
        ldap_server (ldap.LDAPObject): The LDAP server object.
        ciso (str): The CISO to search for.

    Returns:
        list: A list of search results matching the given CISO.
    """
    try:
        search_results = ldap_server.search_s(
            ldap_config.get("auth_ldap_base_dn"),
            ldap.SCOPE_SUBTREE,
            f"(&(mail={ciso})(Tpresent=true)(!(ou=admin))(!(TpreferredFirstName=Test)))",
            ["mail", "title", "businessCategory", "c"],
        )
        return search_results
    except Exception as e:
        print(e)
        return None

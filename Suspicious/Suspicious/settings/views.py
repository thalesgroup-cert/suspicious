import json
import logging
import os
from pathlib import Path

import ldap
from cortex_job.models import Analyzer
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from domain_process.domain_utils.domain_handler import DomainHandler
from domain_process.models import Domain
from file_process.file_utils.file_handler import FileHandler
from hash_process.hash_utils.hash_handler import HashHandler
from hash_process.models import Hash
from profiles.profiles_utils.ldap import Ldap
from settings.models import EmailFeederState
from settings.settings_utils.feeder_email import (check_if_feeder_is_running,
                                                  disable_email_feeder,
                                                  enable_email_feeder)
from settings.settings_utils.filetype import validate_filetype

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

ldap_config = config.get('ldap', {})

logger = logging.getLogger(__name__)

from profiles.models import CISOProfile
from profiles.profiles_utils.ciso import (generate_message, handle_csv_file,
                                          handle_json_file, handle_txt_file,
                                          process_cisos)
from settings.models import (DenyListDomain, Mailbox, AllowListDomain,
                             AllowListFile, AllowListFiletype, CampaignDomainAllowList)
from settings.settings_utils.domain import (generate_message_domain,
                                            handle_bdomain_file,
                                            handle_domain_file,
                                            handle_campaign_domain_file,
                                            preprocess_domains,
                                            process_bdomains, process_domains, process_campaign_domains)
from settings.settings_utils.filetype import (generate_filetype_message,
                                              handle_filetype_csv_file,
                                              handle_filetype_json_file,
                                              handle_filetype_txt_file,
                                              process_filetypes)

CSV_CONTENT_TYPE = 'text/csv'
JSON_CONTENT_TYPE = 'application/json'
TXT_CONTENT_TYPE = 'text/plain'
CASE_NOT_EXIST_ERROR = 'Case does not exist'
JSON_DECODING_ERROR = 'Error decoding JSON file.'
INVALID_REQUEST_OR_NO_FILE_ERROR = 'Invalid request method or no file uploaded.'
INVALID_PARAMETER_ERROR = 'Invalid parameter'
INVALID_FILETYPE_ERROR = 'Invalid file type.'
INVALID_TYPE_ERROR = 'Invalid type'
CSV = 'csv'
JSON = 'json'
TXT = 'txt'


logger = logging.getLogger(__name__)

def logout_view(request):
    """
    Log out the user and redirect to the login page.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponseRedirect: A redirect response to the login page.
    """    
    try:
        # Check if the user is authenticated before trying to log them out
        if request.user.is_authenticated:
            logger.info(f"User {request.user} is logging out")
            logout(request)
            logger.info(f"User {request.user} logged out successfully")
        else:
            logger.warning("Unauthenticated user tried to log out")
    except Exception as e:
        logger.error(f"Error logging out user: {str(e)}", exc_info=True)
    # Always redirect to the login page, regardless of whether the logout was successful
    return redirect('login')

# Settings page

@login_required
def settings(request):
    """
    Handle form submissions for adding and deleting domains to the allow_list.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: The HTTP response object.
    """
    # Fetch all required objects from the database at once to reduce the number of queries
    domain_list, domainB_list, campaign_domain_list, file_list, filetype_list, cisos, analyzer_list = get_settings_data()

    context = {
        'files': file_list,
        'filetypes': filetype_list,
        'cisos': cisos,
        'domains': domain_list,
        'domainsB': domainB_list,
        'campaign_domains': campaign_domain_list,
        'analyzers': analyzer_list
    }
    logger.info(f"User {request.user} is on the settings page")
    return render(request, 'tasp/settings.html', context)


def get_settings_data():
    domain_list = AllowListDomain.objects.all()
    domainB_list = DenyListDomain.objects.all()
    campaign_domain_list = CampaignDomainAllowList.objects.all()
    file_list = AllowListFile.objects.all()
    filetype_list = AllowListFiletype.objects.all()
    cisos = CISOProfile.objects.all()
    analyzers = Analyzer.objects.all()
    analyzer_list = []
    for analyzer in analyzers:
        if analyzer.is_active:
            analyzer_list.append(analyzer)
    return domain_list, domainB_list, campaign_domain_list, file_list, filetype_list, cisos, analyzer_list

## Ciso profiles

@csrf_exempt
def add_ciso_by_upload(request):
    """Handle the upload of a file containing CISO data and process it.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.
    """
    if request.method == 'POST' and request.FILES:
        file = request.FILES['file']
        cisos = []

        # Validate file type based on content type and extension
        allowed_content_types = [CSV_CONTENT_TYPE, JSON_CONTENT_TYPE, TXT_CONTENT_TYPE]
        allowed_extensions = [CSV, JSON, TXT]
        if file.content_type not in allowed_content_types or not file.name.lower().endswith(tuple(allowed_extensions)):
            logger.error(INVALID_FILETYPE_ERROR)
            return JsonResponse({'success': False, 'message': INVALID_FILETYPE_ERROR})

        try:
            if file.content_type == CSV_CONTENT_TYPE:
                cisos = handle_csv_file(file)
            elif file.content_type == JSON_CONTENT_TYPE:
                cisos = handle_json_file(file)
            elif file.content_type == TXT_CONTENT_TYPE:
                cisos = handle_txt_file(file)

            good_cisos, error_cisos = process_cisos(cisos)

            count = len(cisos) - len(good_cisos)
            message = generate_message(good_cisos, error_cisos, count)
            logger.info(message)
            return JsonResponse({'success': True, 'cisos': good_cisos, 'ciso_added_num': len(good_cisos), 'message': message})
        
        except json.JSONDecodeError:
            logger.error(JSON_DECODING_ERROR)
            return JsonResponse({'success': False, 'message': JSON_DECODING_ERROR})
        except ValidationError as e:
            logger.error(str(e))
            return JsonResponse({'success': False, 'message': str(e)})
    
    logger.error(INVALID_REQUEST_OR_NO_FILE_ERROR)
    return JsonResponse({'success': False, 'message': INVALID_REQUEST_OR_NO_FILE_ERROR})



@csrf_exempt
def add_ciso_by_name(request, ciso):
    """Add a CISO to the database by name.

    This function takes a request object and the name of the CISO as input.
    It checks if the CISO already exists in the database and creates a CISO profile if it doesn't exist.
    The CISO profile is created by retrieving information from an LDAP server.
    The function returns a JSON response indicating the success or failure of the operation.

    Args:
        request (HttpRequest): The HTTP request object.
        ciso (str): The name of the CISO to be added.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.
            - If the CISO is successfully added, the response will have 'success' set to True,
              'ciso' set to the name of the added CISO, and 'message' set to a success message.
            - If the CISO already exists in the database, the response will have 'success' set to False
              and 'message' set to an error message indicating that the CISO is already in the database.
            - If the CISO is invalid (i.e., not found in the LDAP server), the response will have 'success' set to False
              and 'message' set to an error message indicating that the CISO is invalid.
    """
    CISO_ADDED_MESSAGE = f'CISO "{ciso}" added to the database.'
    ALREADY_IN_CISO_MESSAGE = f'CISO "{ciso}" already in the database.'
    INVALID_CISO_MESSAGE = f'Invalid CISO: "{ciso}".'

    ciso = ciso.lower()
    try:
        ciso_user = User.objects.get(username=ciso)
        logger.info(f"Username {ciso} found")
        if not CISOProfile.objects.filter(user=ciso_user).exists():
            logger.info(f"Creating CISO profile for user {ciso_user}")
            try:
                ldap_server = Ldap().initialize_ldap()
                search_results = ldap_server.search_s(ldap_config.get("auth_ldap_base_dn"), ldap.SCOPE_SUBTREE,
                    f'(&(mail={ciso})(Tpresent=true)(!(ou=admin))(!(TpreferredFirstName=Test)))',
                    ['mail', 'title', 'businessCategory', 'c'])
                ldap_server.unbind_s()
            except Exception as e:
                print(e)
                search_results = None
            if search_results:
                title = search_results[0][1]['title'][0].decode('utf-8')
                business_category = search_results[0][1]['businessCategory'][0].decode('utf-8')
                CISOProfile.objects.create(user=ciso_user, title=title, business_category=business_category)
                logger.info(f"CISO profile for user {ciso_user} created")
            
            return JsonResponse({'success': True, 'ciso': ciso, 'message': CISO_ADDED_MESSAGE})
        else:
            logger.warning(f"CISO profile for user {ciso_user} already exists")
            return JsonResponse({'success': False, 'message': ALREADY_IN_CISO_MESSAGE})
    except User.DoesNotExist:
        logger.error(f"Username {ciso} not found")
        return JsonResponse({'success': False, 'message': INVALID_CISO_MESSAGE})
    
@csrf_exempt
def remove_ciso_by_name(request, ciso):
    """Remove a CISO from the database by their username.

    Args:
        request (HttpRequest): The HTTP request object.
        ciso (str): The username of the CISO to be removed.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.
            If the CISO is successfully removed, the response will have the following structure:
                {
                    'success': True,
                    'ciso': <username>,
                    'message': <success_message>
                }
            If the CISO is not found in the database, the response will have the following structure:
                {
                    'success': False,
                    'message': <not_found_message>
                }
    """
    SUCCESS_MESSAGE = f'CISO "{ciso}" removed from the database.'
    NOT_FOUND_MESSAGE = f'CISO "{ciso}" not found in the database.'

    ciso = ciso.lower()
    try:
        ciso_user = User.objects.get(username=ciso)
        logger.info(f"CISO with username {ciso} found")
        if CISOProfile.objects.filter(user=ciso_user).exists():
            CISOProfile.objects.filter(user=ciso_user).delete()
            logger.info(f"CISO profile for user {ciso_user} removed from the database")
            return JsonResponse({'success': True, 'ciso': ciso, 'message': SUCCESS_MESSAGE})
        else:
            logger.warning(f"CISO profile for user {ciso_user} not found in the database")
            return JsonResponse({'success': False, 'message': NOT_FOUND_MESSAGE})
    except User.DoesNotExist:
        logger.warning(f"CISO with username {ciso} not found in the database")
        return JsonResponse({'success': False, 'message': NOT_FOUND_MESSAGE})

## DenyList Domain

@csrf_exempt
def add_bdomain_by_upload(request):
    """Handle domain upload and process the uploaded file.

    This function handles the domain upload request and processes the uploaded file.
    It validates the file type based on content type and extension, then calls the necessary functions
    to handle and preprocess the domains. Finally, it processes the domains and generates a response.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing the success status, processed domains, and a message.

    Raises:
        JSONDecodeError: If there is an error decoding the JSON file.
        ValidationError: If there is a validation error during domain processing.
    """
    if request.method == 'POST' and request.FILES:
        file = request.FILES['file']
        domains = []

        # Validate file type based on content type and extension
        allowed_content_types = [CSV_CONTENT_TYPE, JSON_CONTENT_TYPE, TXT_CONTENT_TYPE]
        if file.content_type not in allowed_content_types or not file.name.lower().endswith(('.csv', '.json', '.txt')):
            logger.error(INVALID_FILETYPE_ERROR)
            return JsonResponse({'success': False, 'message': INVALID_FILETYPE_ERROR})

        try:
            domains = handle_bdomain_file(file)
            domains = preprocess_domains(domains)

            good_domains, error_domains = process_bdomains(domains, request.user)

            count = len(domains) - len(good_domains)
            message = generate_message_domain(request.user, good_domains, error_domains, count)
            logger.info(message)
            return JsonResponse({'success': True, 'domains': good_domains, 'domain_added_num': len(good_domains), 'message': message})

        except json.JSONDecodeError:
            logger.error(JSON_DECODING_ERROR)
            return JsonResponse({'success': False, 'message': JSON_DECODING_ERROR})
        except ValidationError as e:
            logger.error(str(e))
            return JsonResponse({'success': False, 'message': str(e)})

    logger.error(INVALID_REQUEST_OR_NO_FILE_ERROR)
    return JsonResponse({'success': False, 'message': INVALID_REQUEST_OR_NO_FILE_ERROR})



@csrf_exempt
def add_bdomain_by_name(request, domain):
    """Add a domain to the deny_list by name.

    This function takes a domain name as input and adds it to the deny_list if it is a valid domain.
    If the domain is already in the deny_list, it returns a failure message.
    If the domain is invalid, it returns an error message.

    Args:
        request (HttpRequest): The HTTP request object.
        domain (str): The domain name to be added to the deny_list.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.

    """
    DOMAIN_ADDED_MESSAGE = f'Domain "{domain}" added to the deny_list.'
    ALREADY_IN_DENY_LIST_MESSAGE = f'Domain "{domain}" already in the deny_list.'
    INVALID_DOMAIN_MESSAGE = f'Invalid domain: "{domain}".'

    domain = domain.lower()
    handled_domain = DomainHandler().validate_domain(domain)
    if handled_domain == "Domain":
        # Get or create the domain object
        domain_db, _ = Domain.objects.get_or_create(value=domain)

        # Add the domain to the deny_list
        if not DenyListDomain.objects.filter(domain=domain_db).exists():
            DenyListDomain.objects.create(domain=domain_db, user=request.user)
            logger.info(f"Domain {domain} added to the deny_list by user {request.user}")
            return JsonResponse({'success': True, 'domain': domain, 'message': DOMAIN_ADDED_MESSAGE})
        else:
            logger.warning(f"Domain {domain} already in the deny_list")
            return JsonResponse({'success': False, 'message': ALREADY_IN_DENY_LIST_MESSAGE})
    elif handled_domain == "Invalid Domain":
        logger.error(f"Invalid domain: {domain}")
        return JsonResponse({'success': False, 'message': INVALID_DOMAIN_MESSAGE})
    else:
        logger.error(f"Invalid domain: {domain}")
        return JsonResponse({'success': False, 'message': INVALID_DOMAIN_MESSAGE})

@csrf_exempt
def remove_bdomain_by_name(request, domain):
    """Remove a domain from the deny_list by name.

    Args:
        request (HttpRequest): The HTTP request object.
        domain (str): The name of the domain to be removed from the deny_list.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.
            If the domain is successfully removed, the response will have the following structure:
                {
                    'success': True,
                    'domain': <removed_domain>,
                    'message': <success_message>
                }
            If the domain is not found in the deny_list, the response will have the following structure:
                {
                    'success': False,
                    'message': <not_found_message>
                }
            If the domain is invalid, the response will have the following structure:
                {
                    'success': False,
                    'message': <invalid_domain_message>
                }
    """
    SUCCESS_MESSAGE = f'Domain "{domain}" removed from deny_list.'
    NOT_FOUND_MESSAGE = f'Domain "{domain}" not found in deny_list.'
    INVALID_DOMAIN_MESSAGE = f'Invalid domain: "{domain}".'

    if DomainHandler().validate_domain(domain) == "Domain":
        try:
            domain_db = Domain.objects.get(value=domain)
            # Remove the domain from the deny_list
            if DenyListDomain.objects.filter(domain=domain_db).exists():
                DenyListDomain.objects.filter(domain=domain_db).delete()
                logger.info(f"Domain {domain} removed from the deny_list by user {request.user}")
                return JsonResponse({'success': True, 'domain': domain, 'message': SUCCESS_MESSAGE})
            else:
                logger.warning(f"Domain {domain} not found in the deny_list")
                return JsonResponse({'success': False, 'message': NOT_FOUND_MESSAGE})
        except Domain.DoesNotExist:
            logger.warning(f"Domain {domain} not found in the database")
            return JsonResponse({'success': False, 'message': NOT_FOUND_MESSAGE})
    else:
        return JsonResponse({'success': False, 'message': INVALID_DOMAIN_MESSAGE})

## Campaign Domain AllowList

@csrf_exempt
def add_campaign_domain_by_upload(request):
    """Handle the upload of a file containing campaign domain data and process it.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.
    """
    if request.method == 'POST' and request.FILES:
        file = request.FILES['file']
        domains = []

        # Validate file type based on content type and extension
        allowed_content_types = [CSV_CONTENT_TYPE, JSON_CONTENT_TYPE, TXT_CONTENT_TYPE]
        allowed_extensions = [CSV, JSON, TXT]
        if file.content_type not in allowed_content_types or not file.name.lower().endswith(tuple(allowed_extensions)):
            logger.error(INVALID_FILETYPE_ERROR)
            return JsonResponse({'success': False, 'message': INVALID_FILETYPE_ERROR})

        try:
            domains = handle_campaign_domain_file(file)
            domains = preprocess_domains(domains)

            good_domains, error_domains = process_campaign_domains(domains, request.user)

            count = len(domains) - len(good_domains)
            message = generate_message_domain(request.user, good_domains, error_domains, count)
            logger.info(message)
            return JsonResponse({'success': True, 'domains': good_domains, 'domain_added_num': len(good_domains), 'message': message})
        
        except json.JSONDecodeError:
            logger.error(JSON_DECODING_ERROR)
            return JsonResponse({'success': False, 'message': JSON_DECODING_ERROR})
        except ValidationError as e:
            logger.error(str(e))
            return JsonResponse({'success': False, 'message': str(e)})
    
    logger.error(INVALID_REQUEST_OR_NO_FILE_ERROR)
    return JsonResponse({'success': False, 'message': INVALID_REQUEST_OR_NO_FILE_ERROR})

@csrf_exempt
def add_campaign_domain_by_name(request, domain):
    """Add a campaign domain to the allow_list by name.

    Args:
        request (HttpRequest): The HTTP request object.
        domain (str): The name of the campaign domain to be added to the allow_list.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.
    """
    DOMAIN_ADDED_MESSAGE = f'Campaign domain "{domain}" added to allow_list.'
    ALREADY_IN_ALLOW_LIST_MESSAGE = f'Campaign domain "{domain}" already in allow_list.'
    INVALID_DOMAIN_MESSAGE = f'Invalid campaign domain: "{domain}".'

    domain = domain.lower()
    if DomainHandler().validate_domain(domain) == "Domain":
        try:
            domain_db = Domain.objects.get(value=domain)
        except Domain.DoesNotExist:
            domain_db = Domain.objects.create(value=domain)

        if not CampaignDomainAllowList.objects.filter(domain=domain_db).exists():
            CampaignDomainAllowList.objects.create(domain=domain_db, user=request.user)
            logger.info(f"Campaign domain {domain} added to the allow_list by user {request.user}")
            return JsonResponse({'success': True, 'domain': domain, 'message': DOMAIN_ADDED_MESSAGE})
        else:
            logger.warning(f"Campaign domain {domain} already in the allow_list")
            return JsonResponse({'success': False, 'message': ALREADY_IN_ALLOW_LIST_MESSAGE})
    else:
        return JsonResponse({'success': False, 'message': INVALID_DOMAIN_MESSAGE})

@csrf_exempt
def remove_campaign_domain_by_name(request, domain):
    """Remove a campaign domain from the allow_list by name.

    Args:
        request (HttpRequest): The HTTP request object.
        domain (str): The name of the campaign domain to be removed from the allow_list.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.
    """
    SUCCESS_MESSAGE = f'Campaign domain "{domain}" removed from allow_list.'
    NOT_FOUND_MESSAGE = f'Campaign domain "{domain}" not found in allow_list.'
    INVALID_DOMAIN_MESSAGE = f'Invalid campaign domain: "{domain}".'

    if DomainHandler().validate_domain(domain) == "Domain":
        try:
            domain_db = Domain.objects.get(value=domain)
            # Remove the campaign domain from the allow_list
            if CampaignDomainAllowList.objects.filter(domain=domain_db).exists():
                CampaignDomainAllowList.objects.filter(domain=domain_db).delete()
                logger.info(f"Campaign domain {domain} removed from the allow_list by user {request.user}")
                return JsonResponse({'success': True, 'domain': domain, 'message': SUCCESS_MESSAGE})
            else:
                logger.warning(f"Campaign domain {domain} not found in the allow_list")
                return JsonResponse({'success': False, 'message': NOT_FOUND_MESSAGE})
        except Domain.DoesNotExist:
            logger.warning(f"Campaign domain {domain} not found in the database")
            return JsonResponse({'success': False, 'message': NOT_FOUND_MESSAGE})
    else:
        return JsonResponse({'success': False, 'message': INVALID_DOMAIN_MESSAGE})

## AllowList Domain

@csrf_exempt
def add_domain_by_upload(request):
    """Handle domain upload and process the uploaded file.

    This function handles the domain upload request and processes the uploaded file.
    It validates the file type based on content type and extension, then calls the necessary functions
    to handle and preprocess the domains. Finally, it processes the domains and generates a response.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing the success status, processed domains, and a message.

    Raises:
        JSONDecodeError: If there is an error decoding the JSON file.
        ValidationError: If there is a validation error during domain processing.
    """
    if request.method == 'POST' and request.FILES:
        file = request.FILES['file']
        domains = []

        # Validate file type based on content type and extension
        allowed_content_types = [CSV_CONTENT_TYPE, JSON_CONTENT_TYPE, TXT_CONTENT_TYPE]
        if file.content_type not in allowed_content_types or not file.name.lower().endswith(('.csv', '.json', '.txt')):
            logger.error(INVALID_FILETYPE_ERROR)
            return JsonResponse({'success': False, 'message': INVALID_FILETYPE_ERROR})

        try:
            domains = handle_domain_file(file)
            domains = preprocess_domains(domains)

            good_domains, error_domains = process_domains(domains, request.user)

            count = len(domains) - len(good_domains)
            message = generate_message_domain(request.user, good_domains, error_domains, count)
            logger.info(message)
            return JsonResponse({'success': True, 'domains': good_domains, 'domain_added_num': len(good_domains), 'message': message})

        except json.JSONDecodeError:
            logger.error(JSON_DECODING_ERROR)
            return JsonResponse({'success': False, 'message': JSON_DECODING_ERROR})
        except ValidationError as e:
            logger.error(str(e))
            return JsonResponse({'success': False, 'message': str(e)})

    logger.error(INVALID_REQUEST_OR_NO_FILE_ERROR)
    return JsonResponse({'success': False, 'message': INVALID_REQUEST_OR_NO_FILE_ERROR})



@csrf_exempt
def add_domain_by_name(request, domain):
    """Add a domain to the allow_list by name.

    This function takes a domain name as input and adds it to the allow_list if it is a valid domain.
    If the domain is already in the allow_list, it returns a failure message.
    If the domain is invalid, it returns an error message.

    Args:
        request (HttpRequest): The HTTP request object.
        domain (str): The domain name to be added to the allow_list.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.

    """
    DOMAIN_ADDED_MESSAGE = f'Domain "{domain}" added to the allow_list.'
    ALREADY_IN_ALLOW_LIST_MESSAGE = f'Domain "{domain}" already in the allow_list.'
    INVALID_DOMAIN_MESSAGE = f'Invalid domain: "{domain}".'

    domain = domain.lower()
    handled_domain = DomainHandler().validate_domain(domain)
    if handled_domain == "Domain":
        # Get or create the domain object
        domain_db, _ = Domain.objects.get_or_create(value=domain)

        # Add the domain to the allow_list
        if not AllowListDomain.objects.filter(domain=domain_db).exists():
            AllowListDomain.objects.create(domain=domain_db, user=request.user)
            logger.info(f"Domain {domain} added to the allow_list by user {request.user}")
            return JsonResponse({'success': True, 'domain': domain, 'message': DOMAIN_ADDED_MESSAGE})
        else:
            logger.warning(f"Domain {domain} already in the allow_list")
            return JsonResponse({'success': False, 'message': ALREADY_IN_ALLOW_LIST_MESSAGE})
    elif handled_domain == "Invalid Domain":
        logger.error(f"Invalid domain: {domain}")
        return JsonResponse({'success': False, 'message': INVALID_DOMAIN_MESSAGE})
    else:
        logger.error(f"Invalid domain: {domain}")
        return JsonResponse({'success': False, 'message': INVALID_DOMAIN_MESSAGE})

@csrf_exempt
def remove_domain_by_name(request, domain):
    """Remove a domain from the allow_list by name.

    Args:
        request (HttpRequest): The HTTP request object.
        domain (str): The name of the domain to be removed from the allow_list.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.
            If the domain is successfully removed, the response will have the following structure:
                {
                    'success': True,
                    'domain': <removed_domain>,
                    'message': <success_message>
                }
            If the domain is not found in the allow_list, the response will have the following structure:
                {
                    'success': False,
                    'message': <not_found_message>
                }
            If the domain is invalid, the response will have the following structure:
                {
                    'success': False,
                    'message': <invalid_domain_message>
                }
    """
    SUCCESS_MESSAGE = f'Domain "{domain}" removed from allow_list.'
    NOT_FOUND_MESSAGE = f'Domain "{domain}" not found in allow_list.'
    INVALID_DOMAIN_MESSAGE = f'Invalid domain: "{domain}".'

    if DomainHandler().validate_domain(domain) == "Domain":
        try:
            domain_db = Domain.objects.get(value=domain)
            # Remove the domain from the allow_list
            if AllowListDomain.objects.filter(domain=domain_db).exists():
                AllowListDomain.objects.filter(domain=domain_db).delete()
                logger.info(f"Domain {domain} removed from the allow_list by user {request.user}")
                return JsonResponse({'success': True, 'domain': domain, 'message': SUCCESS_MESSAGE})
            else:
                logger.warning(f"Domain {domain} not found in the allow_list")
                return JsonResponse({'success': False, 'message': NOT_FOUND_MESSAGE})
        except Domain.DoesNotExist:
            logger.warning(f"Domain {domain} not found in the database")
            return JsonResponse({'success': False, 'message': NOT_FOUND_MESSAGE})
    else:
        return JsonResponse({'success': False, 'message': INVALID_DOMAIN_MESSAGE})

## AllowList File

@csrf_exempt
def add_file_by_upload(request):
    """Handles the file upload and adds the file to the allow_list.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.
    """
    SUCCESS_MESSAGE = 'File added to the database.'
    FILE_ALREADY_EXISTS_MESSAGE = 'File already in allow_list.'
    INVALID_FILE_TYPE_MESSAGE = INVALID_FILETYPE_ERROR

    if request.method == 'POST' and request.FILES:
        file = request.FILES['file']
        try:
            # Validate and hash the file

            hash_value = FileHandler.hash_file(file.temporary_file_path())
            hash_type = HashHandler().validate_hash(hash_value)
            _hash, _ = Hash.objects.get_or_create(value=hash_value, defaults={'hashtype': hash_type})

            # Add the file to the allow_list
            if not AllowListFile.objects.filter(linked_file_hash=_hash).exists():
                AllowListFile.objects.create(linked_file_hash=_hash, user=request.user)
                logger.info(f"File {hash_value} added to the allow_list by user {request.user}")
                return JsonResponse({'success': True, 'file': hash_value, 'message': SUCCESS_MESSAGE})
            else:
                logger.warning(f"File {hash_value} already in the allow_list")
                return JsonResponse({'success': False, 'message': FILE_ALREADY_EXISTS_MESSAGE})
        except Exception as e:
            logger.error(str(e))
            return JsonResponse({'success': False, 'message': str(e)})

    return JsonResponse({'success': False, 'message': INVALID_FILE_TYPE_MESSAGE})

@csrf_exempt
def add_file_by_name(request, file):
    """Add a file to the allow_list by name.

    This function takes a request object and a file name as input and adds the file to the allow_list.
    If the file is already in the allow_list or if it is invalid, appropriate error messages are returned.

    Args:
        request (HttpRequest): The HTTP request object.
        file (str): The name of the file to be added to the allow_list.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation and a message.

    """
    FILE_ADDED_MESSAGE = f'File "{file}" added to the allow_list.'
    ALREADY_IN_ALLOW_LIST_MESSAGE = f'File "{file}" already in the allow_list.'
    INVALID_FILE_MESSAGE = f'Invalid file: "{file}".'

    file = file.lower()
    if HashHandler().validate_hash(file) is not None:
        # Get or create the hash object
        _hash, _ = Hash.objects.get_or_create(value=file, hashtype=HashHandler().validate_hash(file))

        # Add the file to the allow_list
        if not AllowListFile.objects.filter(linked_file_hash=_hash).exists():
            AllowListFile.objects.create(linked_file_hash=_hash, user=request.user)
            logger.info(f"File {file} added to the allow_list by user {request.user}")
            return JsonResponse({'success': True, 'file': file, 'message': FILE_ADDED_MESSAGE})
        else:
            logger.warning(f"File {file} already in the allow_list")
            return JsonResponse({'success': False, 'message': ALREADY_IN_ALLOW_LIST_MESSAGE})
    else:
        logger.error(f"Invalid file: {file}")
        return JsonResponse({'success': False, 'message': INVALID_FILE_MESSAGE})

@csrf_exempt
def remove_file_by_name(request, file):
    """Remove a file from the allow_list by its name.

    Args:
        request (HttpRequest): The HTTP request object.
        file (str): The name of the file to be removed from the allow_list.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.

    Raises:
        None

    """
    SUCCESS_MESSAGE = f'File "{file}" removed from allow_list successfully.'
    NOT_FOUND_MESSAGE = f'File "{file}" not found in allow_list.'
    INVALID_FILE_MESSAGE = f'Invalid file: "{file}".'

    # Validate the file name
    if not HashHandler().validate_hash(file):
        logger.error(INVALID_FILE_MESSAGE)
        return JsonResponse({'success': False, 'message': INVALID_FILE_MESSAGE})

    # Try to get the hash object
    try:
        hash_obj = Hash.objects.get(value=file)
    except Hash.DoesNotExist:
        logger.warning(NOT_FOUND_MESSAGE)
        return JsonResponse({'success': False, 'message': NOT_FOUND_MESSAGE})

    # Try to get the allow_list object
    try:
        allow_list_obj = AllowListFile.objects.get(linked_file_hash=hash_obj)
    except AllowListFile.DoesNotExist:
        logger.warning(NOT_FOUND_MESSAGE)
        return JsonResponse({'success': False, 'message': NOT_FOUND_MESSAGE})

    # Remove the file from the allow_list
    allow_list_obj.delete()
    logger.info(f"File {file} removed from the allow_list by user {request.user}")
    return JsonResponse({'success': True, 'file': file, 'message': SUCCESS_MESSAGE})
    
## AllowList Filetype

@csrf_exempt
def add_filetype_by_upload(request):
    """Handle the upload of a file and add filetypes based on the file's content.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response indicating the success of the operation and any relevant information.

    Raises:
        JSONDecodeError: If there is an error decoding the JSON content of the file.
        ValidationError: If there is a validation error while processing the filetypes.
    """
    if request.method == 'POST' and request.FILES:
        file = request.FILES['file']
        filetypes = []

        # Validate file type based on content type and extension
        allowed_content_types = [CSV_CONTENT_TYPE, JSON_CONTENT_TYPE, TXT_CONTENT_TYPE]
        if file.content_type not in allowed_content_types or not file.name.lower().endswith(('.csv', '.json', '.txt')):
            logger.error(INVALID_FILETYPE_ERROR)
            return JsonResponse({'success': False, 'message': INVALID_FILETYPE_ERROR})

        try:
            content_type_handlers = {
                CSV_CONTENT_TYPE: handle_filetype_csv_file,
                JSON_CONTENT_TYPE: handle_filetype_json_file,
                TXT_CONTENT_TYPE: handle_filetype_txt_file
            }

            if file.content_type in content_type_handlers:
                filetypes = content_type_handlers[file.content_type](file)

            good_filetypes, error_filetypes = process_filetypes(filetypes, request.user)

            count = len(filetypes) - len(good_filetypes)
            message = generate_filetype_message(good_filetypes, error_filetypes, count)
            logger.info(message)
            return JsonResponse({'success': True, 'filetypes': good_filetypes, 'filetype_added_num': len(good_filetypes), 'message': message})

        except json.JSONDecodeError:
            logger.error(JSON_DECODING_ERROR)
            return JsonResponse({'success': False, 'message': JSON_DECODING_ERROR})
        except ValidationError as e:
            logger.error(str(e))
            return JsonResponse({'success': False, 'message': str(e)})
    else:
        logger.error(INVALID_REQUEST_OR_NO_FILE_ERROR)
        return JsonResponse({'success': False, 'message': INVALID_REQUEST_OR_NO_FILE_ERROR})

@csrf_exempt
def add_filetype_by_name(request, filetype):
    """Add a filetype to the allow_list by name.

    This function takes a filetype as input and adds it to the allow_list if it is valid and not already in the allow_list.

    Args:
        request (HttpRequest): The HTTP request object.
        filetype (str): The name of the filetype to be added to the allow_list.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.

    """
    FILETYPE_ADDED_MESSAGE = f'Filetype "{filetype}" added to the allow_list.'
    ALREADY_IN_ALLOW_LIST_MESSAGE = f'Filetype "{filetype}" already in the allow_list.'
    INVALID_FILETYPE_MESSAGE = f'Invalid filetype: "{filetype}".'

    filetype = filetype.lower()
    if validate_filetype(filetype) is not None:
        # Add the filetype to the allow_list
        if not AllowListFiletype.objects.filter(filetype=filetype).exists():
            AllowListFiletype.objects.create(filetype=filetype, user=request.user)
            logger.info(f"Filetype {filetype} added to the allow_list by user {request.user}")
            return JsonResponse({'success': True, 'filetype': filetype, 'message': FILETYPE_ADDED_MESSAGE}, status=201)
        else:
            logger.warning(f"Filetype {filetype} already in the allow_list")
            return JsonResponse({'success': False, 'message': ALREADY_IN_ALLOW_LIST_MESSAGE}, status=409)
    else:
        logger.error(f"Invalid filetype: {filetype}")
        return JsonResponse({'success': False, 'message': INVALID_FILETYPE_MESSAGE}, status=400)

@csrf_exempt
def remove_filetype_by_name(request, filetype):
    """Remove a filetype from the allow_list.

    This function removes a specified filetype from the allow_list. If the filetype is found in the allow_list,
    it will be deleted from the database. Otherwise, an error message will be returned.

    Args:
        request (HttpRequest): The HTTP request object.
        filetype (str): The filetype to be removed from the allow_list.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the operation.

    Raises:
        None

    """
    SUCCESS_MESSAGE = f'Filetype "{filetype}" removed from allow_list successfully.'
    NOT_FOUND_MESSAGE = f'Filetype "{filetype}" not found in allow_list.'

    filetype = filetype.lower()
    # Adjust based on how your Validator class is structured
    if validate_filetype(filetype) is None:
        logger.error(f"Invalid filetype: {filetype}")
        return JsonResponse({'success': False, 'message': f'Invalid filetype: "{filetype}".'})

    try:
        # Remove the filetype from the allow_list
        obj = AllowListFiletype.objects.get(filetype=filetype)
        obj.delete()
        logger.info(f"Filetype {filetype} removed from the allow_list by user {request.user}")
        return JsonResponse({'success': True, 'filetype': filetype, 'message': SUCCESS_MESSAGE})
    except AllowListFiletype.DoesNotExist:
        logger.warning(f"Filetype {filetype} not found in the allow_list")
        return JsonResponse({'success': False, 'message': NOT_FOUND_MESSAGE})

## Modify mailbox

@csrf_exempt
def change_email(request, changed_values):
    """Change email settings.

    This function is responsible for updating the email settings in the mailbox object based on the provided changed values.

    Args:
    request (HttpRequest): The HTTP request object.
    changed_values (str): A comma-separated string containing the changed values for username, password, server, and port.

    Returns:
    JsonResponse: A JSON response indicating the success of the operation and a message.

    """
    if request.method == 'POST':
        changed_values = changed_values.split(',')
        if len(changed_values) != 4:
            return JsonResponse({'success': False, 'message': 'Invalid parameters'})

        changed_username, changed_password, changed_server, changed_port = changed_values

        mailbox, _ = Mailbox.objects.get_or_create(name="From")
        
        update_mailbox(mailbox, changed_username, changed_password, changed_server, changed_port)

        mailbox.save()
        logger.info(f"Mailbox updated with id {mailbox.id}")
        return JsonResponse({'success': True, 'message': 'Email settings updated'})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})

def update_mailbox(mailbox, changed_username, changed_password, changed_server, changed_port):
    if changed_username and changed_username != mailbox.username:
        update_mailbox_username(mailbox, changed_username)

    if changed_password and changed_password != mailbox.password:
        update_mailbox_password(mailbox, changed_password)

    if changed_server and changed_server != mailbox.server:
        update_mailbox_server(mailbox, changed_server)

    if changed_port and changed_port != mailbox.port:
        update_mailbox_port(mailbox, changed_port)

def update_mailbox_username(mailbox, changed_username):
    if changed_username and changed_username != mailbox.username:
        mailbox.username = changed_username

def update_mailbox_password(mailbox, changed_password):
    if changed_password and changed_password != mailbox.password:
        mailbox.password = changed_password

def update_mailbox_server(mailbox, changed_server):
    if changed_server and changed_server != mailbox.server:
        mailbox.server = changed_server

def update_mailbox_port(mailbox, changed_port):
    if changed_port and changed_port != mailbox.port:
        mailbox.port = changed_port

## Update analyzer weights
    
@csrf_exempt
def update_analyzer_weight(request, analyzer_id, weight):
    """Update the weight of an analyzer.

    This function updates the weight of an analyzer identified by `analyzer_id`
    with the provided `weight` value.

    Args:
        request (HttpRequest): The HTTP request object.
        analyzer_id (int): The ID of the analyzer to update.
        weight (float): The new weight value for the analyzer.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the update.
            If the update is successful, the response will have a 'success' key set to True.
            If the analyzer with the given ID does not exist, the response will have a 'success' key set to False
            and an 'error' key with the value 'Analyzer does not exist'.
            If the provided weight is not a valid float, the response will have a 'success' key set to False
            and an 'error' key with the value 'Invalid weight. Weight must be a valid float.'
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Invalid request method. Only POST is allowed.'})

    try:
        analyzer = Analyzer.objects.get(analyzer_cortex_id=analyzer_id)
    except Analyzer.DoesNotExist:
        logger.warning(f"Analyzer with id {analyzer_id} not found")
        return JsonResponse({'success': False, 'error': 'Analyzer does not exist'})

    try:
        new_weight = float(weight)  # Ensure weight is a valid float
    except ValueError:
        logger.warning(f"Invalid weight: {weight}")
        return JsonResponse({'success': False, 'error': 'Invalid weight. Weight must be a valid float.'})

    analyzer.weight = new_weight
    analyzer.save()
    logger.info(f"Analyzer {analyzer.name} updated with weight {analyzer.weight}")
    return JsonResponse({'success': True})

@csrf_exempt
def get_email_feeder_status(request):
    try:
        # Get the latest state from the database
        feeder_state, created = EmailFeederState.objects.get_or_create(id=1)
        return JsonResponse({'status': feeder_state.is_running})
    except Exception as e:
        logger.error(f"Error checking email feeder status: {e}")
        return JsonResponse({'status': 'Unknown'}, status=500)

@csrf_exempt
def toggle_email_feeder(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            status = data.get('status')
            logger.info(f"Toggling email feeder to {'ON' if status else 'OFF'}")
            # Update the state in the database
            feeder_state, created = EmailFeederState.objects.get_or_create(id=1)
            feeder_state.is_running = status
            feeder_state.save()
            
            if status:
                enable_email_feeder()
                logger.info("Email feeder enabled.")
            else:
                disable_email_feeder()
                logger.info("Email feeder disabled.")
            return JsonResponse({'status': status})
        except Exception as e:
            logger.error(f"Error toggling email feeder: {e}")
            return JsonResponse({'status': 'Unknown'}, status=500)

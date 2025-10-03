import base64
import email.header
import json
import logging
import os
import re
from datetime import date
from datetime import datetime as dt
from email.utils import parseaddr
from urllib.parse import urlparse, urlunparse, parse_qs

from dashboard.models import Kpi, MonthlyReporterStats, UserCasesMonthlyStats
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from domain_process.domain_utils.domain_handler import DomainHandler
from email_process.email_utils.email_handler import MailAddressHandler
from email_validator import EmailNotValidError, validate_email
from file_process.file_utils.file_handler import FileHandler
from hash_process.hash_utils.hash_handler import HashHandler
from hash_process.models import Hash
from ip_process.ip_utils.ip_handler import IPHandler
from mail_feeder.mail_utils.meioc import email_analysis
from mail_feeder.mail_utils.similarity_hash import TextDistance
from mail_feeder.models import (ArtifactIsDomain, ArtifactIsHash, ArtifactIsIp,
                                ArtifactIsMailAddress, ArtifactIsUrl, Mail,
                                MailArtifact, MailAttachment, MailBody,
                                MailHeader)
from profiles.profiles_utils.ldap import Ldap
from url_process.url_utils.url_handler import URLHandler

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

company_config = config.get('company_domains', None)
suspicious_config = config.get('suspicious', {})
SUSPICIOUS_EMAIL = suspicious_config.get('email')

fetch_mail_logger = logging.getLogger('tasp.cron.fetch_and_process_emails')
logger = logging.getLogger(__name__)


class MailHandler:
    def __init__(self):
        self.text_distance = TextDistance()
        
    def handle_mail(self, email_data, workdir):
        """
        Handles the email data by checking email lists and either handling a new mail or an existing mail.

        Args:
            email_data (dict): The email data to be handled.

        Returns:
            mail_instance: The instance of the mail that was handled.
        """
        # Validate the email_data before processing

        # Extract the email lists
        email_list, email_body_list, email_header_list = self.check_email_lists(email_data)

        # Check if the lists are empty
        if not email_list and not email_body_list and not email_header_list:
            fetch_mail_logger.debug("handling new mail")
            # If all lists are empty, handle it as a new mail
            mail_instance = self.handle_new_mail(email_data, workdir)
        else:
            # If any of the lists is not empty, handle it as an existing mail
            fetch_mail_logger.debug("handling existing mail")
            mail_instance = self.handle_existing_mail(email_data, email_list, workdir)
        # Validate the mail instance before returning
        if not mail_instance:
            fetch_mail_logger.warning("No mail instance found or created")

        return mail_instance

    def handle_new_mail(self, email_data, workdir):
        """
        Handles a new mail by creating a mail instance, saving and updating it,
        handling rich observables, updating mail times sent, and creating mail info.

        Args:
            email_data (dict): The data of the email.

        Returns:
            MailInstance: The saved mail instance.

        Raises:
            Exception: If an error occurs while handling the mail.
        """
        mail_instance = None
        try:
            mail_instance = self.create_mail_instance(email_data)
            fetch_mail_logger.info(f"Mail instance created: {mail_instance}")
            if mail_instance:
                fetch_mail_logger.debug(f"Mail instance created:")
                mail_instance = self.save_and_update_mail_instance(mail_instance, email_data)
                if mail_instance:
                    fetch_mail_logger.info(f"Mail instance saved and updated: {mail_instance}")
                    self.handle_rich_observables(mail_instance.mail_id, mail_instance, email_data, workdir)
                    fetch_mail_logger.info(f"Rich observables handled")
                    self.update_mail_times_sent(mail_instance)
                    fetch_mail_logger.info(f"Mail times sent updated")
                mail_instance = self.save_mail_instance(mail_instance)
                fetch_mail_logger.info(f"Mail instance saved: {mail_instance}")
        except Exception as e:
            fetch_mail_logger.error(f"Error handling mail as first seen: {str(e)}")
        return mail_instance

    def handle_existing_mail(self, email_data, email_list, workdir):
        """
        Handles an existing mail instance.

        Args:
            email_data (dict): The data of the email.
            email_list (list): List of existing email instances.
            email_body_list (list): List of email bodies.
            email_header_list (list): List of email headers.

        Returns:
            mail_instance: The updated or newly created mail instance.
        """
        mail_instance = None
        try:
            if email_list:
                mail_instance = email_list[0]
                self.update_mail_times_sent(mail_instance)
            else:
                mail_instance = self.handle_new_mail(email_data, workdir)
        except Exception as e:
            fetch_mail_logger.error(f"Error handling mail as already seen: {str(e)}")
        return mail_instance

    def save_and_update_mail_instance(self, mail_instance, email_data):
        """
        Saves and updates the mail instance with the provided email data.

        Args:
            mail_instance (Mail): The mail instance to be saved and updated.
            email_data (dict): The email data used to create related instances.

        Returns:
            Mail: The saved and updated mail instance.
        """
        if not mail_instance or not isinstance(mail_instance, Mail) or not email_data:
            raise ValueError("Invalid mail instance or email data provided")

        # Save the mail instance
        mail_instance = self.save_mail_instance(mail_instance)

        # Create and save mail body instance
        mail_body_instance = self.create_mail_body_instance(email_data)
        if mail_instance:
            if mail_body_instance:
                self.save_mail_body_instance(mail_body_instance)
                mail_instance.mail_body = mail_body_instance

            # Create and save mail header instance
            mail_header_instance = self.create_mail_header_instance(email_data)
            if mail_header_instance:
                self.save_mail_header_instance(mail_header_instance)
                mail_instance.mail_header = mail_header_instance

        # Save the updated mail instance
        mail_instance = self.save_mail_instance(mail_instance)

        return mail_instance

    def update_existing_mail_instance(self, mail_instance, email_data, email_body_list, email_header_list):
        """
        Updates an existing mail instance with the provided email data, email body list, and email header list.

        Args:
            mail_instance (Mail): The existing mail instance to be updated.
            email_data (dict): The email data containing information to update the mail instance.
            email_body_list (list): The list of existing email bodies.
            email_header_list (list): The list of existing email headers.

        Returns:
            Mail: The updated mail instance.
        """
        # Check if mail_instance is valid
        if not mail_instance or not isinstance(mail_instance, Mail):
            raise ValueError("Invalid mail instance")

        # Check if email_data is valid
        if not email_data or not isinstance(email_data, dict):
            raise ValueError("Invalid email data")
        
        # Handle mail body
        if email_body_list:
            existing_mail_body = email_body_list[0]
            self.update_mail_body_times_sent(existing_mail_body)
            mail_instance.mail_body = existing_mail_body
        else:
            mail_body_instance = self.create_mail_body_instance(email_data)
            if mail_body_instance:
                self.save_mail_body_instance(mail_body_instance)
                mail_instance.mail_body = mail_body_instance

        # Handle mail header
        if email_header_list:
            existing_mail_header = email_header_list[0]
            mail_instance.mail_header = existing_mail_header
        else:
            mail_header_instance = self.create_mail_header_instance(email_data)
            if mail_header_instance:
                self.save_mail_header_instance(mail_header_instance)
                mail_instance.mail_header = mail_header_instance

        # Save and return the updated mail instance
        mail_instance = self.save_mail_instance(mail_instance)
        return mail_instance

    def check_email_lists(self, email_data):
        """
        Check the email lists for a given email data.

        Args:
            email_data (dict): A dictionary containing email data.

        Returns:
            tuple: A tuple containing the following lists:
                - email_list: A list of Mail objects filtered by mail_id.
                - email_body_list: A list of email bodies that passed the validation.
                - email_header_list: A list of email headers that passed the validation.
        """
        # fetch_mail_logger.info(f"Checking email lists for email data")
        # Extract data from email_data
        email_id = email_data.get('id')
        email_data_body = email_data.get('reportedText')
        email_data_header = email_data.get('headers')
        # fetch_mail_logger.info("Email data extracted")
        # Get the list of Mail objects filtered by mail_id
        email_list = Mail.objects.filter(mail_id=str(email_id))
        # fetch_mail_logger.info("list of Mail objects filtered by mail_id")
        # Check and validate email bodies and headers
        email_body_list = self.check_email_bodies(email_data_body) if email_data_body else []
        # fetch_mail_logger.info("Email body processed")
        # fetch_mail_logger.info(f"Email body list: {email_body_list}")
        email_header_list = self.check_email_headers(email_data_header) if email_data_header else []
        # fetch_mail_logger.info("Email header processed")
        # fetch_mail_logger.info(f"Email header list: {email_header_list}")
        return email_list, email_body_list, email_header_list

    def check_email_bodies(self, email_data_body):
        """
        Check the email bodies for similarity with the given email data body.

        Args:
            email_data_body (str): The email data body to compare with.

        Returns:
            list: A list of email bodies that are similar to the given email data body.
        """
        email_body_list = []
        # try:
        #     # Filter emails that have a non-null mail_body and possibly narrow down further
        #     fetch_mail_logger.info("Filtering emails with non-null mail_body")
        #     emails = Mail.objects.filter(~Q(mail_body__isnull=True)).select_related('mail_body')
        #     fetch_mail_logger.info(f"Number of emails with non-null mail_body: {emails.count()}")
        #     # fuzzy_hash = self.text_distance.hash_text_mail(str(email_data_body))
        #     fuzzy_hash = self.text_distance.hash_text_mail(str(email_data_body))
        #     fetch_mail_logger.info(f"Fuzzy hash: {fuzzy_hash}")
        #     for email in emails:
        #         stored_hash = email.mail_body.fuzzy_hash
        #         # distance = self.text_distance.calculate_distance(email.mail_body.fuzzy_hash, fuzzy_hash)
        #         distance = self.text_distance.calculate_distance(fuzzy_hash,stored_hash)
        #         if distance < 1:
        #             fetch_mail_logger.info(f"Distance: {distance}")
        #             email_body_list.append(email.mail_body)
        #             email.mail_body.times_sent = F('times_sent') + 1
        #             if distance == 0:
        #                 email.times_sent = F('times_sent') + 1
        #                 email.save(update_fields=['times_sent'])
        #                 break
        #             email.mail_body.other_values = self.text_distance.preprocess_text(str(email_data_body))
        #             email.mail_body.save(update_fields=['times_sent', 'other_values'])
        #             email.save(update_fields=['times_sent'])
        #             break
                    
        # except Exception as e:
        #     print(f"Error checking email body lists: {str(e)}")
            
        return email_body_list

    def check_email_headers(self, email_data_header):
        """
        Check and validate email headers.

        This method checks the email headers against the existing mail headers in the database.
        It calculates the distance between the email header and the headers in the database using a text distance algorithm.
        If the distance is less than 1, it adds the mail header to the email_header_list.
        If the distance is 0, it increments the times_sent counter of the email and breaks the loop.
        It also updates the other_values field of the mail header with preprocessed text and saves the changes.

        Args:
            email_data_header (str): The email header to be checked and validated.

        Returns:
            list: A list of mail headers that match the email_data_header.

        Raises:
            Exception: If there is an error while checking the email header lists.
        """
        email_header_list = []
        # try:
        #     # Filter emails that have a non-null mail_header and prefetch related objects
        #     fetch_mail_logger.info("Filtering emails with non-null mail_header")

        #     emails = Mail.objects.filter(~Q(mail_header__isnull=True)).select_related('mail_header')
        #     fetch_mail_logger.info(f"Number of emails with non-null mail_header: {emails.count()}")
        #     #fuzzy_hash = self.text_distance.hash_text_mail(str(email_data_header))
        #     fuzzy_hash = self.text_distance.hash_text(str(email_data_header))
        #     for email in emails:
        #         stored_hash = self.text_distance.hash_text(email.mail_header.header_value)
        #         distance_header = self.text_distance.calculate_distance(fuzzy_hash,stored_hash)
        #         if distance_header < 1:
        #             fetch_mail_logger.info(f"Distance: {distance_header}")
        #             email_header_list.append(email.mail_header)
        #             email.mail_header.times_sent = F('times_sent') + 1
        #             if distance_header == 0:
        #                 email.times_sent = F('times_sent') + 1
        #                 email.save(update_fields=['times_sent'])
        #                 break
        #             email.mail_header.other_values = self.text_distance.preprocess_text(str(email_data_header))
        #             email.mail_header.save(update_fields=['times_sent', 'other_values'])
        #             email.save(update_fields=['times_sent'])
        #             break
                    
        # except Mail.DoesNotExist as e:
        #     print(f"Mail object does not exist: {str(e)}")
        # except Exception as e:
        #     print(f"Error checking email header lists: {str(e)}")
            
        return email_header_list

    def create_mail_instance(self, email_data):
        """
        Create a Mail instance based on the provided email data.

        Args:
            email_data (dict): A dictionary containing the email data.

        Returns:
            Mail or None: The created Mail instance, or None if creation failed.
        """
        subject = str(email_data.get('reportedSubject', ''))
        _from = str(email_data.get('reportedBy', ''))
        name, addr = parseaddr(_from)
        decoded_subject = self.decode_subject(subject) or f"Suspicious Mail by {_from or 'Unknown Sender'}"

        to_field = str(email_data.get('to', ''))
        if not _from or not to_field:
            fetch_mail_logger.warning(f"Skipping mail creation: missing required fields reportedBy='{_from}', to='{to_field}'")
            return None

        try:
            mail_instance = Mail(
                subject=decoded_subject,
                reportedBy=addr,
                date=self.parse_date(email_data.get('date', date.today().strftime("%a, %d %b %Y %H:%M:%S %z"))),
                mail_from=str(email_data.get('from', '')),
                to=to_field,
                cc=str(email_data.get('cc', '')),
                bcc=str(email_data.get('bcc', '')),
                mail_id=str(email_data.get('id', '')),
            )
            mail_instance.full_clean()  # Validate the instance
            mail_instance.save()        # Save the instance
        except Exception as e:
            fetch_mail_logger.error(f"Error creating mail instance: {e}")
            return None

        return mail_instance


    @staticmethod
    def decode_subject(subject):
        """
        Decode the subject of the email.

        Args:
            subject (str): The subject of the email.

        Returns:
            str: The decoded subject.
        """
        decoded_subject = ""
        for part, encoding in email.header.decode_header(subject):
            if isinstance(part, bytes):
                decoded_subject += part.decode(encoding or 'utf-8', errors='replace')
            else:
                decoded_subject += part
        return decoded_subject

    @staticmethod
    def parse_date(date_string):
        """
        Parse the date string into a datetime object.

        Args:
            date_string (str): The date string.

        Returns:
            datetime: The parsed datetime object.
        """
        try:
            if date_string is None:
                return dt.now()
            return dt.strptime(str(date_string), "%a, %d %b %Y %H:%M:%S %z").replace(tzinfo=None)
        except ValueError:
            return dt.now()

    def save_mail_instance(self, mail_instance):
        """
        Saves the given mail instance and returns it if successful.

        Args:
            mail_instance: The mail instance to be saved.

        Returns:
            The saved mail instance if successful, None otherwise.
        """
        try:
            mail_instance.save()
            return mail_instance
        except Exception as e:
            fetch_mail_logger.error(f"Error saving mail instance: {str(e)}")
            return None
        

    def create_mail_body_instance(self, email_data):
        """
        Create a MailBody instance based on the provided email data.

        Args:
            email_data (dict): A dictionary containing the email data.

        Returns:
            MailBody: The created MailBody instance.
        """
        # Extract the reported text from the email data
        reported_text = str(email_data.get('reportedText', ''))

        # If the reported text is empty, return None or raise an exception
        if not reported_text:
            # You can choose to return None or raise an exception
            # return None
            raise ValueError("Reported text is empty")

        # Calculate the fuzzy hash of the reported text
        fuzzy_hash = self.text_distance.hash_text_mail(reported_text)

        # Try to get the MailBody instance with the calculated fuzzy hash
        mail_body_instance, created = MailBody.objects.get_or_create(
            fuzzy_hash=fuzzy_hash,
            defaults={'body_value': reported_text}
        )

        # If the MailBody instance was created now, it means it did not exist before
        if created:
            # You can add any additional logic here if needed
            pass

        return mail_body_instance

    
    def create_mail_header_instance(self, email_data):
        """
        Create a MailHeader instance based on the provided email data.

        Args:
            email_data (dict): A dictionary containing email data.

        Returns:
            MailHeader: The created MailHeader instance.

        Raises:
            None.

        """
        # Extract the headers from the email data
        headers = str(email_data.get('headers', ''))

        # If the headers are empty, return None or raise an exception
        if not headers:
            raise ValueError("Email data does not contain headers")

        # Calculate the fuzzy hash of the headers
        fuzzy_hash = self.text_distance.hash_text_mail(headers)

        # Try to get the MailHeader instance with the calculated fuzzy hash
        try:
            mail_header_instance = MailHeader.objects.get(fuzzy_hash=fuzzy_hash)
        except MailHeader.DoesNotExist:
            # If the MailHeader instance does not exist, create a new one
            mail_header_instance = MailHeader(
                header_value=headers,
                fuzzy_hash=fuzzy_hash
            )

        return mail_header_instance
    
    def save_mail_body_instance(self, mail_body_instance):
        """
        Saves the given mail body instance.

        Args:
            mail_body_instance: The mail body instance to be saved.

        Raises:
            Exception: If there is an error while saving the mail body instance.
        """
        try:
            mail_body_instance.save()
        except Exception as e:
            # Instead of just printing the error, let's log it for better debugging and tracking
            fetch_mail_logger.error(f"Error saving mail body instance: {str(e)}")
            # Reraise the exception after logging it
            raise

    def save_mail_header_instance(self, mail_header_instance):
        """
        Saves the given mail header instance.

        Args:
            mail_header_instance: The mail header instance to be saved.

        Raises:
            Exception: If there is an error while saving the mail header instance.
        """
        try:
            mail_header_instance.save()
        except Exception as e:
            # Instead of just printing the error, let's log it so that it can be tracked in a logging system
            fetch_mail_logger.error(f"Error saving mail header instance: {str(e)}")
            # Reraise the exception after logging so that it can be handled upstream if necessary
            raise

    def handle_rich_observables(self, filename, mail_instance, email_data, workdir):
        """
        Handles rich observables extracted from an email.

        Args:
            filename (str): The name of the file.
            mail_instance: An instance of the mail.
            email_data: The data of the email.

        Raises:
            Exception: If there is an error handling rich observables.

        Returns:
            None
        """
        try:
            rich_observables = self.extract_observables_v3(filename, email_data, workdir)
            artifacts = rich_observables.get('artifacts', [])
            files = rich_observables.get('files', [])
            if artifacts:
                self.handle_mail_artifacts(artifacts, mail_instance)
            if files:
                self.handle_mail_attachment(files, mail_instance)
        except Exception as e:
            # Instead of printing the error, it's better to log it for debugging purposes
            fetch_mail_logger.error(f"Error handling rich observables: {str(e)}")
            # Re-raise the exception after logging it
            raise

    def update_mail_times_sent(self, mail_instance):
        """
        Update the number of times a mail has been sent and save the changes.

        Args:
            mail_instance: An instance of the Mail model.

        Raises:
            Exception: If there is an error updating the mail times sent.

        """
        mail_instance.times_sent += 1
        try:
            mail_instance.save()
        except Exception as e:
            fetch_mail_logger.error(f"Error updating mail times sent: {str(e)}")


    def update_mail_body_times_sent(self, existing_mail_body):
        """
        Updates the 'times_sent' attribute of an existing mail body object and saves it.

        Parameters:
        existing_mail_body (MailBody): The existing mail body object to update.

        Returns:
        None
        """
        try:
            existing_mail_body.times_sent += 1
            existing_mail_body.save()
        except Exception as e:
            fetch_mail_logger.error(f"An error occurred while updating the 'times_sent' attribute: {e}")
            # Optionally, you can re-raise the exception if you want the error to propagate
            # raise

    def handle_mail_artifacts(self, artifacts, mail_instance):
        """
        Handle mail artifacts.

        Args:
            artifacts (list): List of artifacts.
            mail_instance (Mail): Mail instance.

        Returns:
            None
        """
        # Define a dictionary to map data types to their respective handler methods
        data_type_handlers = {
            'mail': self.handle_mail_artifact_mail,
            'domain': self.handle_mail_artifact_domain,
            'url': self.handle_mail_artifact_url,
            'ip': self.handle_mail_artifact_ip,
            'hash': self.handle_mail_artifact_hash,
        }

        for artifact in artifacts:
            try:
                data_type = artifact['dataType']
                data_value = artifact['data']
                
                if data_type == 'file':
                    pass  # Skip file artifacts
                else:
                    fetch_mail_logger.debug(f"Data type: {data_type}, Data value: {data_value}")
                    # Use the dictionary to get the handler method for the current data type
                    handler = data_type_handlers.get(data_type)
                    fetch_mail_logger.debug(f"Handler: {str(handler)}")
                    if handler:
                        fetch_mail_logger.debug(f"Handler found for data type: {data_type}")
                        # Call the handler method with the data value and mail instance
                        handler(data_value, mail_instance)
                        fetch_mail_logger.debug(f"Handler called for data type: {data_type}")
                    else:
                        fetch_mail_logger.warning(f"Unknown data type: {data_type}")

            except Exception as e:
                fetch_mail_logger.error(f"Error handling artifact: {e}")

    def handle_mail_artifact_mail(self, data_value, mail_instance):
        """
        Handle the mail artifact for the given data value and mail instance.

        Args:
            data_value (str): The data value to handle.
            mail_instance (MailInstance): The mail instance object.

        Returns:
            None
        """
        artifact = MailArtifact.objects.filter(mail=mail_instance, artifact_type="MailAddress", artifactIsMailAddress__mail_address__address=data_value.lower()).first()
        if artifact:
            fetch_mail_logger.debug(f"Mail address artifact already exists for {data_value}")
            return
        handler_method = self.get_handler_method('mail')
        handler = self.get_handler('mail')
        if handler_method:
            artifact = handler_method(handler, data_value)
        if artifact:
            try:
                with transaction.atomic():
                    mail_artifact = MailArtifact.objects.create(mail=mail_instance, artifact_type="MailAddress")
                    data_value = data_value.lower()
                    if company_config:
                        is_valid, valid_email = is_valid_email(data_value)
                        if is_valid:
                            if is_valid_company_email(data_value):
                                self.get_or_create_user(data_value)
                            else:
                                self.create_artifact_is_mail_address(artifact, mail_artifact, valid_email, mail_instance)
                    mail_artifact.save()
                    mail_instance.save()
            except Exception as e:
                fetch_mail_logger.error(f"Unexpected error while saving mail artifact: {str(e)}")

    def create_artifact_is_mail_address(self, artifact, mail_artifact, data_value, mail_instance):
        """
        Creates an ArtifactIsMailAddress object and associates it with the given artifact and mail_artifact.
        If the ArtifactIsMailAddress object already exists for the given mail address, it updates the association with the mail_instance.

        Args:
            artifact: The mail address artifact.
            mail_artifact: The mail artifact.
            data_value: The mail address value.
            mail_instance: The mail instance to associate with the ArtifactIsMailAddress object.

        Returns:
            None
        """
        try:
            artifact_is_mail_address, created = ArtifactIsMailAddress.objects.get_or_create(mail_address__address=data_value, defaults={'mail_address': artifact, 'artifact': mail_artifact})
            artifact_is_mail_address.save()
            mail_artifact.artifactIsMailAddress = artifact_is_mail_address
        except Exception as e:
            fetch_mail_logger.error(f"Error creating/updating ArtifactIsMailAddress: {str(e)}")

    def handle_mail_artifact_domain(self, data_value, mail_instance):
        """
        Handles the mail artifact domain.

        Args:
            data_value (str): The data value of the domain.
            mail_instance (Mail): The mail instance.

        Returns:
            None
        """
        artifact = MailArtifact.objects.filter(mail=mail_instance, artifact_type="Domain", artifactIsDomain__domain__value=data_value.lower()).first()
        if artifact:
            fetch_mail_logger.debug(f"Domain artifact already exists for {data_value}")
            return
        try:
            handler_method = self.get_handler_method('domain')
            handler = self.get_handler('domain')
            artifact = handler_method(handler, data_value) if handler_method else None
            if artifact:
                mail_artifact = MailArtifact.objects.create(mail=mail_instance, artifact_type='Domain')
                data_value = data_value.lower()
                artifact_is_domain, _ = ArtifactIsDomain.objects.get_or_create(domain__value=data_value,
                                                                                     defaults={'domain': artifact,
                                                                                               'artifact': mail_artifact})
                artifact_is_domain.save()
                if mail_artifact:
                    mail_artifact.artifactIsDomain = artifact_is_domain
                    mail_artifact.save()
                    mail_instance.save()
        except Exception as e:
            fetch_mail_logger.error(f"Error handling mail artifact domain: {str(e)}")

    def get_prime_and_decoded_url(self, url):
        """
        Retrieves the prime URL (without query parameters) and decodes the Base64-encoded 'tid' param from the URL.

        Args:
            url (str): The URL to process.

        Returns:
            tuple: A tuple containing the prime URL and the decoded URL (if any).
        """
        def get_prime_url(url):
            parsed_url = urlparse(url)
            return urlunparse(parsed_url._replace(query='', fragment=''))

        def decode_base64_from_tid_param(url):
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                tid = params.get('tid', [None])[0]
                if tid:
                    # Add padding if needed
                    padded = tid + '=' * (-len(tid) % 4)
                    decoded = base64.urlsafe_b64decode(padded).decode('utf-8')
                    return decoded
            except Exception as e:
                fetch_mail_logger.error(f"Error decoding Base64: {e}")
            return None

        prime_url = get_prime_url(url)
        decoded_url = decode_base64_from_tid_param(url)

        return prime_url, decoded_url

    def handle_mail_artifact_url(self, data_value, mail_instance):
        """
        Handles the mail artifact URL, processing both the prime URL and the decoded URL.

        Args:
            data_value (str): The data value of the URL.
            mail_instance (Mail): The mail instance.

        Returns:
            None
        """
        url, decoded_url = self.get_prime_and_decoded_url(data_value)
        seen_urls = set()

        try:
            for candidate_url in [url, decoded_url]:
                if candidate_url and candidate_url not in seen_urls:
                    seen_urls.add(candidate_url)
                    self.process_url(candidate_url, mail_instance)
        except Exception as e:
            fetch_mail_logger.error(f"Error handling mail artifact URL: {str(e)}")


    def process_url(self, url, mail_instance, artifact_type='URL'):
        """
        Processes the URL, creates or updates the MailArtifact, and associates it with the mail instance.

        Args:
            url (str): The URL to be processed.
            mail_instance (Mail): The mail instance to associate the artifact with.
            artifact_type (str): The type of artifact (default is 'URL').

        Returns:
            None
        """
        # Skip if already linked to this mail
        artifact = MailArtifact.objects.filter(mail=mail_instance, artifact_type=artifact_type, artifactIsUrl__url__address=url).first()
        if artifact:
            fetch_mail_logger.debug(f"URL artifact already exists for {url}")
            return

        handler_method = self.get_handler_method('url')
        handler = self.get_handler('url')
        artifact = None

        if handler_method:
            artifact = handler_method(handler, url)

        if artifact and artifact[0]:
            mail_artifact = MailArtifact.objects.create(mail=mail_instance, artifact_type=artifact_type)

            artifact_is_url, _ = ArtifactIsUrl.objects.get_or_create(
                url__address=url,
                defaults={'url': artifact[0], 'artifact': mail_artifact}
            )

            mail_artifact.artifactIsUrl = artifact_is_url
            mail_artifact.save()

            mail_instance.save()

            fetch_mail_logger.info(f"Processed URL: {url}")
        else:
            fetch_mail_logger.error(f"Failed to process {artifact_type} artifact for {url}")


    def save_mail_artifact(self, mail_artifact, mail_instance):
        """
        Saves the mail artifact and associates it with the given mail instance.

        Args:
            mail_artifact (MailArtifact): The mail artifact to be saved.
            mail_instance (MailInstance): The mail instance to associate the artifact with.

        Raises:
            Exception: If there is an error while saving the mail artifact.

        """
        try:
            with transaction.atomic():  # Use Django's atomic to ensure database operations are atomic
                mail_artifact.save()
                mail_instance.mail_artifacts.add(mail_artifact)
                mail_instance.save()
        except Exception as e:
            fetch_mail_logger.error(f"Error saving mail artifact: {str(e)}")
            raise e  # Re-raise the exception after logging it

    def handle_mail_artifact_ip(self, data_value, mail_instance):
        """
        Handles the mail artifact for IP addresses.

        Args:
            data_value (str): The IP address value.
            mail_instance (Mail): The mail instance.

        Returns:
            None
        """
        artifact = MailArtifact.objects.filter(mail=mail_instance, artifact_type="IP", artifactIsIp__ip__address=data_value.lower()).first()
        if artifact:
            fetch_mail_logger.debug(f"IP artifact already exists for {data_value}")
            return
        try:
            handler_method = self.get_handler_method('ip')
            handler = self.get_handler('ip')
            if handler_method:
                artifact = handler_method(handler, data_value)
            if artifact:
                mail_artifact = MailArtifact.objects.create(mail=mail_instance, artifact_type='IP')
                artifact_is_ip, _ = ArtifactIsIp.objects.get_or_create(ip__address=data_value, defaults={'ip': artifact, 'artifact': mail_artifact})
                artifact_is_ip.save()
                mail_artifact.artifactIsIp = artifact_is_ip
                mail_artifact.save()
                mail_instance.save()
        except Exception as e:
            fetch_mail_logger.error(f"Error handling mail artifact IP: {str(e)}")

    def handle_mail_artifact_hash(self, data_value, mail_instance):
        """
        Handles the mail artifact hash by creating a mail artifact and associating it with the provided mail instance.

        Args:
            data_value (str): The value of the data to be hashed.
            mail_instance (Mail): The mail instance to associate the mail artifact with.

        Returns:
            None
        """
        artifact = MailArtifact.objects.filter(mail=mail_instance, artifact_type="Hash", artifactIsHash__hash__value=data_value.lower()).first()
        if artifact:
            fetch_mail_logger.debug(f"Hash artifact already exists for {data_value}")
            return
        handler_method = self.get_handler_method('hash')
        handler = self.get_handler('hash')
        artifact = None
        if handler_method:
            artifact = handler_method(handler, data_value)
        if artifact:
            mail_artifact = MailArtifact.objects.create(mail=mail_instance, artifact_type='Hash')
            hash_obj, _ = Hash.objects.get_or_create(value=data_value)
            artifact_is_hash, _ = ArtifactIsHash.objects.get_or_create(hash=hash_obj, artifact=mail_artifact)
            artifact_is_hash.save()
            mail_artifact.artifactIsHash = artifact_is_hash
            try:
                mail_artifact.save()
                mail_instance.save()
            except Exception as e:
                fetch_mail_logger.error(f"Error saving mail artifact: {str(e)}")


    def get_handler(self, data_type):
        handler_methods = {
            'ip': IPHandler,
            'hash': HashHandler,
            'url': URLHandler,
            'domain': DomainHandler,
            'mail': MailAddressHandler
        }
        return handler_methods.get(data_type)

    def get_handler_method(self, data_type):
        handler_methods = {
            'ip': IPHandler.handle_ip,
            'hash': HashHandler.handle_hash,
            'url': URLHandler.handle_url,
            'domain': DomainHandler.handle_domain,
            'mail': MailAddressHandler.handle_mail
        }
        return handler_methods.get(data_type)

    def handle_mail_attachment(self, files, mail_instance):
        """
        Handles mail attachments by saving them to the database and associating them with the given mail instance.

        Args:
            files (dict): A dictionary of file objects representing the attachments.
            mail_instance (Mail): The mail instance to associate the attachments with.

        Returns:
            None
        """

        for file_obj in files.values():
            filename = file_obj.name
            try:
                att, _ = FileHandler.handle_file(file=None, mail=filename)
                if att is not None:
                    mail_attachment = MailAttachment(mail=mail_instance, file=att)
                    mail_attachment.save()
            except Exception as e:
                fetch_mail_logger.error(f"Error handling attachment: {e}")
        mail_instance.save()

    def get_or_create_user(self, username):
        """
        Retrieves an existing user from the database or creates a new user if not found.

        Args:
            username (str): The username of the user to retrieve or create.

        Returns:
            User: The retrieved or created user object.

        Raises:
            Exception: If an error occurs while retrieving the user from the database.
        """
        today = date.today()
        month = today.strftime("%m")  # This will ensure the month is always 2 digits
        year = today.year
        user = None
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist:
            is_valid, valid_email = is_valid_email(username)
            if is_valid:
                username = valid_email
                if is_valid_company_email(username):
                    user = self.create_user(username)
                else:
                    fetch_mail_logger.warning("No User Found, Defaulting user...")
                    user = self.create_default_user()

            # These operations are common to both cases, so we can move them out of the if-else block
            self.update_kpi_stats(month, year)
            self.create_monthly_user_stats(user, month, year)
            Ldap.create_user(user)

        except Exception as e:
            fetch_mail_logger.error(f"An error occurred while retrieving user {username} from the database: {e}")

        return user

    def create_user(self, username):
        """
        Creates a new user with the given username.

        Args:
            username (str): The username for the new user.

        Returns:
            User: The newly created user object.
        """
        if not username:
            raise ValueError("Username cannot be empty")

        try:
            User.objects.get(username=username)
            fetch_mail_logger.warning("User: (%s) already exists!" % username)
            return None
        except User.DoesNotExist:
            try:
                user = User.objects.create_user(username=username, password=None)
                user.set_unusable_password()
                user.full_clean()  # Validate the model
                user.save()
                fetch_mail_logger.info("User: (%s) created !" % username)
                return user
            except Exception as e:
                fetch_mail_logger.warning("Error creating user: ", e)
                return None
                
    def update_kpi_stats(self, month, year):
        """
        Update the KPI statistics for a given month and year.

        Args:
            month (int): The month for which the statistics are being updated.
            year (int): The year for which the statistics are being updated.
        """
        # Use Django's get_or_create to avoid try-except block
        from tasp.cron import sync_monthly_kpi
        sync_monthly_kpi()
        kpi=Kpi.objects.get(month=month, year=year)
        # If Kpi instance already exists, update the MonthlyReporterStats instance
        try:
            kpi.monthly_reporter_stats.new_reporters += 1
            kpi.monthly_reporter_stats.total_reporters += 1
        except Exception as e:
            # Log the exception for debugging
            fetch_mail_logger.error(f"Exception occurred: {e}")
            # Create a new MonthlyReporterStats instance if it does not exist
            monthly_reporter_stats = MonthlyReporterStats.objects.create(
                new_reporters=1,
                total_reporters=1,
            )
            kpi.monthly_reporter_stats = monthly_reporter_stats
        
        kpi.monthly_reporter_stats.save()

        # Save the Kpi instance
        kpi.save()

    def create_monthly_user_stats(self, user, month, year):
        """
        Create or update the monthly user statistics for a given user, month, and year.

        Args:
            user (User): The user for whom the statistics are being created or updated.
            month (int): The month for which the statistics are being created or updated.
            year (int): The year for which the statistics are being created or updated.

        Returns:
            None
        """
        # Use Django's get_or_create to avoid try-except block
        monthly_user_stats, _ = UserCasesMonthlyStats.objects.get_or_create(user=user, month=month, year=year)

        # If the UserCasesMonthlyStats instance was created, you can add any additional setup here

        # Save the UserCasesMonthlyStats instance
        monthly_user_stats.save()

    def create_default_user(self):
        """
        Creates a default user if it doesn't already exist.

        If a user with the username "suspicious@cert.local" already exists, it returns that user.
        Otherwise, it creates a new user with the username "suspicious@cert.local" and sets an unusable password.

        Returns:
            User: The default user.
        """
        username = SUSPICIOUS_EMAIL
        user, created = User.objects.get_or_create(username=username)
        if created:
            user.set_unusable_password()
            user.save()
        return user

    def extract_observables_v3(self, filename, mail, workdir):
        """
        Extracts observables from an email and its attachments.

        Args:
            filename (str): The name of the email file.
            mail (dict): The metadata of the email.

        Returns:
            dict: A dictionary containing the extracted artifacts and files.

        Raises:
            FileNotFoundError: If the email file or any of its attachments are not found.
        """
        def add_artifact(data_type, data, tags=None):
            """
            Add an artifact to the list of artifacts.

            Parameters:
            - data_type (str): The type of data for the artifact.
            - data (any): The data for the artifact.
            - tags (list, optional): A list of tags for the artifact.

            Returns:
            None
            """
            if not data_type or not data:
                raise ValueError("Both data_type and data are required to add an artifact")

            artifact = {'dataType': data_type, 'data': data}
            if tags:
                if not isinstance(tags, list):
                    raise TypeError("tags must be a list")
                artifact['tags'] = tags
            artifacts.append(artifact)

        def add_file_attachment(file_path, attachment_id, tags=None):
            """
            Add a file attachment to the `files` dictionary and associate it with an artifact.

            Args:
                file_path (str): The path to the file to be attached.
                attachment_id (int): The ID of the attachment.
                tags (list, optional): A list of tags to associate with the attachment. Defaults to None.

            Returns:
                int: The ID of the next attachment.

            Raises:
                FileNotFoundError: If the file to be attached is not found.
            """
            if file_path not in processed_files:
                processed_files.add(file_path)  # Track the file path as processed
                files[str(attachment_id)] = open(file_path, 'rb')
                add_artifact('file', str(attachment_id), tags)
                return attachment_id + 1
            return attachment_id  # Return the same ID if file was already added

        def process_attachments(directory, attachment_id, tags):
            """
            Process attachments in the given directory.

            Args:
                directory (str): The directory path where the attachments are located.
                attachment_id (int): The ID of the attachment.
                tags (list): A list of tags associated with the attachments.

            Returns:
                int: The updated attachment ID after processing all attachments.
            """
            # Use os.scandir() instead of os.listdir() for better performance
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_file() and not re.match(r'\d{6}-[0-9a-f]{5}.eml', entry.name):
                        file_path = os.path.join(directory, entry.name)
                        attachment_id = add_file_attachment(file_path, attachment_id, tags)
            return attachment_id

        artifacts = []
        files = {}
        processed_files = set()  # Keep track of added file paths to avoid duplicates

        # Generate observables list using meioc library + attached files
        filepath = None
        eml_path = os.path.join(workdir, f"{filename}.eml")
        msg_path = os.path.join(workdir, f"{filename}.msg")

        if os.path.exists(eml_path):
            filepath = eml_path
        elif os.path.exists(msg_path):
            filepath = msg_path
        else:
            eml_path = os.path.join(workdir, "user_submission.eml")
            msg_path = os.path.join(workdir, "user_submission.msg")
            if os.path.exists(eml_path):
                filepath = eml_path
            elif os.path.exists(msg_path):
                filepath = msg_path
            else:
                raise FileNotFoundError(f"Neither '{eml_path}' nor '{msg_path}' exists.")
        try:
            fetch_mail_logger.debug(f"Beginning")
            iocextract = json.loads(email_analysis(filepath, True, True, True, False))
        except Exception as e:
            fetch_mail_logger.debug(f"Error : {e}")
        fetch_mail_logger.debug(f"iocex : {iocextract}")
        # Adding observables of type urls, domains, attachment, ip, email, hash
        if iocextract['urls']:
            for url in iocextract['urls']:
                if iocextract['urls'][url].startswith('mailto'):
                    continue
                add_artifact('url', iocextract['urls'][url])
        if iocextract['domains']:
            for domain in iocextract['domains']:
                add_artifact('domain', iocextract['domains'][domain])
        if iocextract['body_ip']:
            for ip in iocextract['body_ip']:
                add_artifact('ip', str(ip), ['Body'])
        if iocextract['body_email']:
            for email_add in iocextract['body_email']:
                add_artifact('mail', str(email_add), ['Body'])
        if iocextract['body_hash']:
            for hash_art in iocextract['body_hash']:
                add_artifact('hash', str(hash_art), ['Body'])
        # Purging eml file if the attachment was an msg file
        if mail.get('mailFormat') == 'msg':
            os.remove(filepath)
            filepath = os.path.join(FILE_TEMP_PATH, filename, f"{filename}.msg")
        # Working on attached files
        attachment_id = 0
        attachment_tags = ['reported email']
        attachment_id = add_file_attachment(filepath, attachment_id, attachment_tags)
        linked_att_path = workdir+"/attachments"
        if os.path.exists(linked_att_path):
            if os.listdir(linked_att_path):
                attachment_id = process_attachments(linked_att_path, attachment_id, ['from reported email'])
        if 'parent' in mail:
            parent_directory = os.path.join(workdir, mail['parent'])
            attachment_id = process_attachments(parent_directory, attachment_id, ['from parent email'])

        return {'artifacts': artifacts, 'files': files}

def is_valid_email(email):
    try:
        # Valide l'adresse email et retourne sa forme normalisée
        valid = validate_email(email, check_deliverability=False)
        return True, valid.email
    except EmailNotValidError as e:
        return False, str(e)

def is_valid_company_email(email):
    try:
        # Validate email syntax and deliverability
        valid = False
        v = validate_email(email)
        normalized_email = v.email
        domain = normalized_email.split('@')[1].lower()
        for company_domain in company_config:
            company_domain = company_domain.lower()
            if domain == company_domain:
                valid = True
        return valid
    except EmailNotValidError:
        return False
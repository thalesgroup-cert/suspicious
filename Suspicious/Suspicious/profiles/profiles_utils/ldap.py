import os
import ldap
import ldap.filter
from django.contrib.auth.models import Group
from profiles.models import CISOProfile, UserProfile
from django.contrib.auth import get_user_model
import json
from pathlib import Path

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

ldap_config = config.get('ldap', {})

# Django auth group names that also carry real RBAC meaning (api/permissions,
# SUBMISSION_ELEVATED_GROUPS). LDAP-derived attribute values (title/
# businessCategory) must never be allowed to silently join one of these —
# see add_user_to_group.
RESERVED_GROUP_NAMES = {"Admin", "CERT", "CISO"}

CISO = {
    "CISO",
    "RSSI",
    "Responsable de la Seguridad de la Información",
    "Responsable de la Sécurité des Systèmes d'Information",
    "Chief Information Security Officer",
}
REGION_DICT = {
    "LATAM": ["AR", "BO", "BR", "CL", "CO", "MX", "PE", "UY", "VE"],
    "NORAM": ["BS", "CA", "CR", "DO", "GT", "HN", "HT", "JM", "MX", "NI", "PA", "PR", "SV", "US"],
    "EMEA": ["AE", "AT", "AZ", "BE", "BG", "BH", "CM", "CI", "CZ", "DE", "DZ", "DK", "EE", "EG", "ES", "ET", "FI", "FR",
                "GB", "GR", "HK", "HU", "IE", "IL", "IQ", "IT", "JO", "KE", "KW", "KZ", "LB", "LT", "LU", "LV", "MA", "MD", "MK",
                "MT", "MY", "NG", "NL", "NO", "OM", "PK", "PL", "PT", "QA", "RO", "RS", "RU", "SA", "SE", "SG", "SI", "SK", "SN",
                "SY", "TD", "TN", "TR", "UA", "UG", "UZ", "ZA"],
    "APAC": ["AU", "CN", "HK", "ID", "IN", "JP", "KR", "MY", "NZ", "PH", "SG", "TH", "TW", "VN"]
}


class Ldap:
    
    
    def initialize_ldap(self):
        """
        Initializes and returns an LDAP server connection.

        This method sets the required TLS options, initializes an LDAP server connection,
        and performs a simple bind operation using the provided bind DN and password.

        Returns:
            ldap_server (ldap.LDAPObject): The initialized LDAP server connection.

        Raises:
            LDAPError: If there is an error while binding to the LDAP server.

        """
        try:
            # verify_ssl defaults to secure (OPT_X_TLS_DEMAND); explicit
            # opt-out only. Previously this unconditionally set
            # OPT_X_TLS_NEVER, disabling certificate verification on every
            # bind regardless of config and exposing bind credentials to
            # MITM on the network path.
            verify_ssl = str(ldap_config.get("auth_ldap_verify_ssl", "True")).lower()
            if verify_ssl in ("false", "0", "no"):
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            else:
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            ldap_server = ldap.initialize(ldap_config.get("auth_ldap_server_uri", "ldap://localhost"))
            ldap_server.simple_bind_s(ldap_config.get("auth_ldap_bind_dn", "cn=admin,dc=example,dc=com"),
                                    ldap_config.get("auth_ldap_bind_password", "password"))
            return ldap_server
        except ldap.LDAPError as e:
            print(f"Error while binding to the LDAP server: {e}")
            raise
    
    @staticmethod
    def get_search_results(instance, ldap_server):
        """
        Get search results from the LDAP server.

        Args:
            instance: The instance of the user.
            ldap_server: The initialized LDAP server.

        Returns:
            search_results: The search results from the LDAP server.
        """
        try:
            print('searching user')
            # instance.username can be attacker/IdP-controlled (e.g. OIDC
            # preferred_username); escape it so LDAP metacharacters can't
            # widen or restructure the search filter.
            safe_username = ldap.filter.escape_filter_chars(instance.username)
            search_results = ldap_server.search_s(ldap_config.get("auth_ldap_base_dn"), ldap.SCOPE_SUBTREE,
                                                  f'(&(mail={safe_username})(Tpresent=true)(!(ou=admin))(!(TpreferredFirstName=Test)))',
                                                  ['mail', 'title', 'businessCategory', 'c'])
            print(search_results)
        except Exception as e:
            print(e)
            search_results = None
        return search_results

    @staticmethod
    def process_search_results(instance, search_results):
        """
        Process the search results and create user profiles.

        Args:
            instance: The instance of the user.
            search_results: The search results from the LDAP server.

        Returns:
            None
        """
        ciso_found = False
        if search_results:
            try:
                for title in CISO:
                    if title in search_results[0][1]['title'][0].decode('utf-8'):
                        ciso_found = True
                        print('CISO found')
                        break
                if ciso_found:
                    Ldap.create_ciso_profile(instance, search_results)
                else:
                    print('Not a CISO')
                    Ldap.create_user_profile(instance, search_results)
            except Exception as e:
                print(e)

    @staticmethod
    def create_ciso_profile(instance, search_results):
        """
        Creates a CISO profile for the given instance.

        Args:
            instance: The instance of the user.
            search_results: The search results from the LDAP server.

        Returns:
            None
        """
        ciso_profile, _ = CISOProfile.objects.get_or_create(user=instance)
        ciso_profile.gbu = search_results[0][1]['businessCategory'][0].decode('utf-8')
        ciso_profile.function = search_results[0][1]['title'][0].decode('utf-8')
        ciso_profile.country = search_results[0][1]['c'][0].decode('utf-8')
        for region in REGION_DICT:
            if search_results[0][1]['c'][0].decode('utf-8') in REGION_DICT[region]:
                ciso_profile.region = region
                break
        ciso_profile.save()
        Ldap.add_user_to_group(instance, ciso_profile.country)
        Ldap.add_user_to_group(instance, ciso_profile.region)
        Ldap.add_user_to_group(instance, ciso_profile.gbu)

    @staticmethod
    def create_user_profile(instance, search_results):
        """
        Creates a user profile for the given instance.

        Args:
            instance: The instance of the user.
            search_results: The search results from the LDAP server.

        Returns:
            None
        """
        user_profile, _ = UserProfile.objects.get_or_create(user=instance)
        user_profile.gbu = search_results[0][1]['businessCategory'][0].decode('utf-8')
        user_profile.function = search_results[0][1]['title'][0].decode('utf-8')
        user_profile.country = search_results[0][1]['c'][0].decode('utf-8')
        for region in REGION_DICT:
            if search_results[0][1]['c'][0].decode('utf-8') in REGION_DICT[region]:
                user_profile.region = region
                break
        user_profile.save()
        Ldap.add_user_to_group(instance, user_profile.country)
        Ldap.add_user_to_group(instance, user_profile.region)
        Ldap.add_user_to_group(instance, user_profile.gbu)

    @staticmethod
    def create_user(instance):
        """
        Creates a user profile for the given instance.

        Args:
            instance: The instance of the user.

        Returns:
            None
        """
        searched_user = get_user_model().objects.filter(username=instance.username)
        if instance.username == 'AdminCert':
            return
        if instance.username == 'suspicious@cert.local':
            return
        elif searched_user:
            ldap_server = Ldap().initialize_ldap()
            search_results = Ldap.get_search_results(instance, ldap_server)
            Ldap.process_search_results(instance, search_results)
            ldap_server.unbind_s()

    @staticmethod
    def add_user_to_group(user, group_name):
        # LDAP directory attributes (title/businessCategory/country/region)
        # must never be allowed to grant membership in a group that also
        # carries RBAC meaning — otherwise a directory value of e.g. "Admin"
        # silently grants real app privileges on the next sync.
        if group_name in RESERVED_GROUP_NAMES:
            print(f"Refusing to add user {user.username!r} to LDAP-derived "
                  f"group {group_name!r}: name collides with a reserved RBAC group.")
            return
        try:
            group, _ = Group.objects.get_or_create(name=group_name)
        except Group.DoesNotExist:
            group = Group.objects.create(name=group_name)
        user.groups.add(group)
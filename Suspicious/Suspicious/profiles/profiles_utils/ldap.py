import logging

try:
    import ldap
    import ldap.filter
except ImportError:
    ldap = None  # type: ignore[assignment]
from django.contrib.auth.models import Group
from profiles.models import CISOProfile, UserProfile
from django.contrib.auth import get_user_model

logger = logging.getLogger("profiles.ldap")

RESERVED_GROUP_NAMES = {"Admin", "CERT", "CISO"}


def _ldap_config() -> dict:
    from settings.config import get_section
    return get_section("authentication.ldap")


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
        ldap_config = _ldap_config()
        try:
            verify_ssl = str(ldap_config.get("verify_ssl", "True")).lower()
            if verify_ssl in ("false", "0", "no"):
                logger.warning(
                    "LDAP TLS verification disabled via settings.json "
                    "(authentication.ldap.verify_ssl=false). Bind credentials "
                    "are exposed to MITM."
                )
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            else:
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            ldap_server = ldap.initialize(ldap_config.get("server_uri", "ldap://localhost"))
            ldap_server.simple_bind_s(ldap_config.get("bind_dn", "cn=admin,dc=example,dc=com"),
                                    ldap_config.get("bind_password", "password"))
            return ldap_server
        except ldap.LDAPError as e:
            logger.error(f"Error while binding to the LDAP server: {e}")
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
            safe_username = ldap.filter.escape_filter_chars(instance.username)
            search_results = ldap_server.search_s(_ldap_config().get("base_dn"), ldap.SCOPE_SUBTREE,
                                                  f'(&(mail={safe_username})(Tpresent=true)(!(ou=admin))(!(TpreferredFirstName=Test)))',
                                                  ['mail', 'title', 'businessCategory', 'c'])
        except Exception as e:
            logger.error(f"LDAP search failed for user {instance.username!r}: {e}")
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
                        break
                if ciso_found:
                    Ldap.create_ciso_profile(instance, search_results)
                else:
                    Ldap.create_user_profile(instance, search_results)
            except Exception as e:
                logger.error(f"Failed to process LDAP search results for user {instance.username!r}: {e}")

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
        if group_name in RESERVED_GROUP_NAMES:
            logger.warning(
                "Refusing to add user %r to LDAP-derived group %r: name collides "
                "with a reserved RBAC group.", user.username, group_name,
            )
            return
        group, _ = Group.objects.get_or_create(name=group_name)
        user.groups.add(group)

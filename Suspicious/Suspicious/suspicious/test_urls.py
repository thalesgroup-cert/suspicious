# test_urls.py — URL configuration for the test suite.
#
# test_settings.py points ROOT_URLCONF here. It now simply re-exports the
# real project URLConf: the test image (suspicious:django61 / suspicious:ci)
# has the system libs (libmagic, libldap) the api/ view tree needs, so the
# historical "stub to avoid importing api/" workaround — and the piecemeal
# route-registration it forced — is no longer necessary.
from suspicious.urls import urlpatterns  # noqa: F401

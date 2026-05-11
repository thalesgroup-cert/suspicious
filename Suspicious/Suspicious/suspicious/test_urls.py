# test_urls.py — empty URL configuration for use during unit tests.
#
# The test runner uses --settings=suspicious.test_settings which points
# ROOT_URLCONF here.  This avoids importing the full api/ view tree,
# which depends on system libraries (libmagic, libldap) that are not
# present outside Docker.

urlpatterns: list = []

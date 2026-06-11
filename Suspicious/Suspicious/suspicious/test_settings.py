# test_settings.py — minimal overrides for the local test runner.
#
# Inherits everything from suspicious.settings, then:
#   • Replaces ROOT_URLCONF with a stub so Django's system check
#     doesn't try to import every view/service module (many require
#     system libs like libmagic / libldap that are not available outside
#     the Docker container).
#
# Usage:
#   SUSPICIOUS_CONFIG_PATH=/path/settings.json \
#   python manage.py test --settings=suspicious.test_settings <label>

from suspicious.settings import *  # noqa: F401,F403

# Replace the real URL conf with a minimal stub that satisfies Django's
# system check without importing any heavy service modules.
ROOT_URLCONF = "suspicious.test_urls"

# Run Celery tasks synchronously in tests so on_commit callbacks can
# execute deliver_event.delay() without a live broker.
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True


from suspicious.settings import *  # noqa: F401,F403

ROOT_URLCONF = "suspicious.test_urls"

CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

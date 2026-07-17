import logging

from common.safe_exec import make_safe_execution

logger = logging.getLogger(__name__)

safe_execution = make_safe_execution("EmailBodyService", logger)

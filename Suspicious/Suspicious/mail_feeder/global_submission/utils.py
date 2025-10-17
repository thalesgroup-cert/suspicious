import logging
from contextlib import contextmanager
from typing import List, Union

logger = logging.getLogger("global_submissions")


@contextmanager
def safe_execution(context: str):
    """
    Standardized try/except wrapper for logging and exception propagation.
    """
    try:
        yield
    except Exception as e:
        logger.error(f"[global_submissions] Error during {context}: {e}", exc_info=True)
        raise


def flatten_id_lists(*lists: List[Union[int, List[int]]]) -> List[int]:
    """
    Flattens multiple lists of IDs into a single list.
    """
    return [i for sublist in lists for i in (sublist if isinstance(sublist, list) else [sublist])]

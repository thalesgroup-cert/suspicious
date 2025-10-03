import logging
import docker

# --- Logging setup ---
if not logging.getLogger().hasHandlers():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

logger = logging.getLogger(__name__)

# --- Docker configuration ---
DOCKER_CONTAINER_NAME = 'email_feeder'

# Docker client
docker_client = docker.from_env()

# --- Core Functions ---
def check_if_feeder_is_running() -> bool:
    """
    Check whether the Docker container for the email feeder is currently running.
    """
    logger.info(f"Checking if Docker container '{DOCKER_CONTAINER_NAME}' is running...")
    try:
        container = docker_client.containers.get(DOCKER_CONTAINER_NAME)
        if container.status == 'running':
            logger.info(f"Container '{DOCKER_CONTAINER_NAME}' is currently running.")
            return True
        else:
            logger.info(f"Container '{DOCKER_CONTAINER_NAME}' is in status '{container.status}'.")
            return False
    except docker.errors.NotFound:
        logger.warning(f"Container '{DOCKER_CONTAINER_NAME}' not found.")
        return False
    except Exception as e:
        logger.error(f"Unexpected error while checking container status: {e}")
        return False

def enable_email_feeder() -> bool:
    """
    Start the Docker container running the email feeder logic.
    Returns True if the container was started successfully or is already running.
    """
    if check_if_feeder_is_running():
        logger.info(f"Email feeder container '{DOCKER_CONTAINER_NAME}' is already running. No action taken.")
        return True

    logger.info(f"Attempting to start Docker container '{DOCKER_CONTAINER_NAME}'...")
    try:
        container = docker_client.containers.get(DOCKER_CONTAINER_NAME)
        container.start()
        logger.info(f"Container '{DOCKER_CONTAINER_NAME}' started successfully.")

        if check_if_feeder_is_running():
            logger.info("Verification successful: Email feeder container is running.")
            return True
        else:
            logger.warning("Container start command issued but container still not running.")
            return False
    except docker.errors.NotFound:
        logger.error(f"Container '{DOCKER_CONTAINER_NAME}' not found. Cannot start it.")
        return False
    except Exception as e:
        logger.error(f"Error starting container '{DOCKER_CONTAINER_NAME}': {e}")
        return False

def disable_email_feeder() -> bool:
    """
    Stop the Docker container running the email feeder logic.
    Returns True if the container was stopped successfully or was already stopped.
    """
    if not check_if_feeder_is_running():
        logger.info(f"Email feeder container '{DOCKER_CONTAINER_NAME}' is already stopped. No action taken.")
        return True

    logger.info(f"Attempting to stop Docker container '{DOCKER_CONTAINER_NAME}'...")
    try:
        container = docker_client.containers.get(DOCKER_CONTAINER_NAME)
        container.stop()
        logger.info(f"Container '{DOCKER_CONTAINER_NAME}' stopped successfully.")

        if not check_if_feeder_is_running():
            logger.info("Verification successful: Email feeder container is stopped.")
            return True
        else:
            logger.warning("Container stop command issued but container still appears to be running.")
            return False
    except docker.errors.NotFound:
        logger.error(f"Container '{DOCKER_CONTAINER_NAME}' not found. Cannot stop it.")
        return False
    except Exception as e:
        logger.error(f"Error stopping container '{DOCKER_CONTAINER_NAME}': {e}")
        return False

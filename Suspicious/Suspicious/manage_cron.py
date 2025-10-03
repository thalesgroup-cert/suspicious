import os
import django
import logging
import argparse
import docker

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'suspicious.settings')
django.setup()

# Import models
from settings.models import EmailFeederState

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Docker client
docker_client = docker.from_env()
DOCKER_CONTAINER_NAME = "email_feeder"

def enable_email_feeder():
    """
    Start the Docker container for the email feeder.
    """
    try:
        container = docker_client.containers.get(DOCKER_CONTAINER_NAME)
        if container.status != 'running':
            container.start()
            logger.info("Email feeder container started.")
        else:
            logger.info("Email feeder container is already running.")
    except docker.errors.NotFound:
        logger.error(f"Container '{DOCKER_CONTAINER_NAME}' not found.")
    except Exception as e:
        logger.error(f"Error starting container '{DOCKER_CONTAINER_NAME}': {e}")

def disable_email_feeder():
    """
    Stop the Docker container for the email feeder.
    """
    try:
        container = docker_client.containers.get(DOCKER_CONTAINER_NAME)
        if container.status == 'running':
            container.stop()
            logger.info("Email feeder container stopped.")
        else:
            logger.info("Email feeder container is already stopped.")
    except docker.errors.NotFound:
        logger.error(f"Container '{DOCKER_CONTAINER_NAME}' not found.")
    except Exception as e:
        logger.error(f"Error stopping container '{DOCKER_CONTAINER_NAME}': {e}")

def show_feeder_status():
    """
    Show current status of the feeder container.
    """
    try:
        container = docker_client.containers.get(DOCKER_CONTAINER_NAME)
        logger.info(f"Email feeder container status: {container.status}")
    except docker.errors.NotFound:
        logger.error(f"Container '{DOCKER_CONTAINER_NAME}' not found.")
    except Exception as e:
        logger.error(f"Error retrieving status of container '{DOCKER_CONTAINER_NAME}': {e}")

def manage_feeder_state(state=None):
    """
    Manage Docker container for the feeder based on DB or CLI state.
    Args:
        state (str): Optional. If 'on' or 'off', it will enable or disable the feeder directly.
    """
    try:
        if state:
            if state.lower() == 'on':
                enable_email_feeder()
                logger.info('Feeder container started based on command-line argument "on".')
            elif state.lower() == 'off':
                disable_email_feeder()
                logger.info('Feeder container stopped based on command-line argument "off".')
            else:
                logger.error('Invalid argument. Use "on" or "off".')
            return

        # Fallback: use database state
        db_state = EmailFeederState.objects.first()
        if db_state and db_state.is_running:
            enable_email_feeder()
            logger.info('Feeder container started based on EmailFeederState being ON.')
        else:
            disable_email_feeder()
            logger.info('Feeder container stopped based on EmailFeederState being OFF.')
    except Exception as e:
        logger.error(f'Error managing feeder container: {e}')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage Email Feeder Docker Container")
    parser.add_argument(
        "--state",
        choices=["on", "off"],
        help="Manually set the email feeder container state to 'on' or 'off'."
    )
    args = parser.parse_args()

    # Manage feeder based on input
    manage_feeder_state(args.state)

    # Show current container status
    show_feeder_status()

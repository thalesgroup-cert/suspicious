import sys
from pathlib import Path

# The analyzer modules are flat siblings of tests/ (they are imported as
# top-level modules inside the Docker images), so put that folder on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

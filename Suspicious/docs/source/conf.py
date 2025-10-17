import django
import os
import sys

sys.path.insert(0, os.path.abspath('/app/Suspicious'))

from django.conf import settings

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'suspicious.settings')
django.setup()

project = 'Suspicious'
copyright = '2025, Theo Bhang, Esteban Crispel'
author = 'Theo Bhang, Esteban Crispel'
release = '1.0.0'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'myst_parser',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']
myst_heading_anchors = 3
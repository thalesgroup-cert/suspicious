"""Stub for python-magic when libmagic is not installed (docs build only)."""
import types

class Magic:
    def __init__(self, **kw): pass
    def from_buffer(self, *a, **kw): return 'application/octet-stream'
    def from_file(self, *a, **kw): return 'application/octet-stream'

def from_buffer(buf, *a, **kw): return 'application/octet-stream'
def from_file(path, *a, **kw): return 'application/octet-stream'

"""The submission queue was never wired in and has been removed.

The app stays installed only so migration 0003 can drop its table; delete the
whole directory (and its INSTALLED_APPS entry) once every environment has
migrated past 0003.
"""

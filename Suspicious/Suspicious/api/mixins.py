from datetime import datetime
from rest_framework.exceptions import ValidationError


class MonthYearQueryMixin:
    """
    Robust helper to extract and normalize month/year from query params.

    - Defaults to current month/year if missing
    - Validates ranges
    - Normalizes for CharField storage (MM / YYYY)
    """

    DEFAULT_TO_NOW = True

    def get_month_year(self):
        now = datetime.now()

        raw_month = self.request.query_params.get("month")
        raw_year = self.request.query_params.get("year")

        # Defaults
        if not raw_month and self.DEFAULT_TO_NOW:
            month = now.month
        else:
            month = self._parse_month(raw_month)

        if not raw_year and self.DEFAULT_TO_NOW:
            year = now.year
        else:
            year = self._parse_year(raw_year)

        # Normalized strings (for CharField compatibility)
        month_str = f"{int(month):02d}"
        year_str = str(int(year))

        return month_str, year_str

    # -------------------------------------------------------------

    @staticmethod
    def _parse_month(value):
        try:
            month = int(value)
        except (TypeError, ValueError):
            raise ValidationError({"month": "Month must be an integer between 1 and 12"})

        if not 1 <= month <= 12:
            raise ValidationError({"month": "Month must be between 1 and 12"})

        return month

    @staticmethod
    def _parse_year(value):
        try:
            year = int(value)
        except (TypeError, ValueError):
            raise ValidationError({"year": "Year must be a valid integer"})

        if year < 2000 or year > 2100:
            raise ValidationError({"year": "Year out of supported range (2000–2100)"})

        return year

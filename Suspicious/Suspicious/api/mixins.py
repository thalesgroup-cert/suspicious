from datetime import datetime


class MonthYearQueryMixin:
    """
    Extracts month/year from query params.
    Defaults to current month/year.
    """

    def get_month_year(self):
        now = datetime.now()
        month = int(self.request.query_params.get("month", now.month))
        year = int(self.request.query_params.get("year", now.year))
        return month, year

from django.db.models import Q


def exactly_one_not_null(*fields: str) -> Q:
    """Q that holds when exactly one of ``fields`` is not NULL."""
    terms = []
    for field in fields:
        term = Q(**{f"{field}__isnull": False})
        for other in fields:
            if other != field:
                term &= Q(**{f"{other}__isnull": True})
        terms.append(term)
    result = terms[0]
    for term in terms[1:]:
        result |= term
    return result

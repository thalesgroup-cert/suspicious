from rest_framework.exceptions import ValidationError

def parse_int_query_param(request, name: str, *, required=True, min_value=None, max_value=None):
    raw = request.query_params.get(name)

    if raw in (None, ""):
        if required:
            raise ValidationError({name: "This query parameter is required."})
        return None

    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValidationError({name: "Must be an integer."})

    if min_value is not None and value < min_value:
        raise ValidationError({name: f"Must be >= {min_value}."})
    if max_value is not None and value > max_value:
        raise ValidationError({name: f"Must be <= {max_value}."})

    return value
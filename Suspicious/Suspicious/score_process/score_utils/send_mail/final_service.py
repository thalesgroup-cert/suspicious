# mail_service/final_service.py
import json
from urllib.parse import urlparse
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import FinalMailServiceConfigSocial
from .send_email_service import SendMailService
from .email_theme import resolve_email_theme
from .email_logo import resolve_logo
from case_handler.models import CaseChallengeToken

CONFIG_PATH = "/app/settings.json"
TEMPLATES_DIR = Path(__file__).parent / "templates"

SOCIAL_LOGOS = {
    "linkedin": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEIAAABCCAYAAADjVADoAAABS2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDIgNzkuMTYwOTI0LCAyMDE3LzA3LzEzLTAxOjA2OjM5ICAgICAgICAiPgogPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIi8+CiA8L3JkZjpSREY+CjwveDp4bXBtZXRhPgo8P3hwYWNrZXQgZW5kPSJyIj8+nhxg7wAAA09JREFUeJzt3EuoHEUUxvHftEJEiVcwiigE34oomQtXBI0xiojgUlH3rlyYhUIkoCCIm5gs1IVuVQTFTdyKRBME8YU3vsDHIosEhGuUCC4kyS0XVa2TsacncWrSfdP9h15M1Zk+p7853VNV3acHIQQ1LOJh3IVrcUmdcQtZwc/Yh3ewPMlwMEGIRezG3fOIrkE+wpP4aryjqDDejs+cfSLAVvHYto93jGbEAC/hiTMWVrO8gm3lh9GM2KE7IhCP9Z/MKDNiEZ/jnIaCaooTWMJymRG7dU8E4jG/SMyIoYqraMcYFuI4oes8UmBL01G0gC2DEMIKNjQdScOsDEIIq+IYosusFnoRoKgaYneSczPv7xj24zCux23WSMblFOIAHhKnvSW3411cntHPXBiEKQsSp8hR3IhfKvqW8KnqmW5ryBXcG6pFgC/EhZFWk0uI76f0f5vJz9zIJcS0AVnrB2y5rhHfYIjVir4FHMRFGfzMjVwZcQt2+u9f5Tq8qeUikC8jSvbhdRzCDXgcN2Xc/9zILcSapdX/7WeSnCPLPeIQe5zz8cBY24f4tcJ2g39vIxzFa3gP3+EPrMfVuF9cfL1i5qhLQj4WQggqto0Vtpsn2G5O/XtCCBdPsCm3dSGEnbmCb+Op8RYexJEpdn+Jy/HP5nDaNiEO4jFxmf1UeQGfzOq4bUIcEn/p0yHg+Vkdt02I/8v7+H2WHbRViGvwqpjyH+M5XFBjfwJfzuIw9wpVDjaJI9SFkbY70nafeCpUcXgWp23MiF1OFqHkXvWPKvw2i9O2CbEe99T01/Wd7kX2JNomxFXqY9o4L8dtE+LCKf1zu2PfNiEaoxci0QuR6IVI9EIkeiESvRCJXohEL0SiFyKRcxq+FX9WtF9a0baE8yrab57i4zJxFlrFlVO+W0t/gyfRnxqJXohEL0SiFyLRC5EoTF4V7hKrhen3GLvAkQI/NB1FC/ixEB8Z7jr7+1KmyLAQy4T3Nh1Jg3yAA2W541B8VLhrlX7HcauRcsdlPNNcPI2xQyqcHy+Sf1l3qoEnlkRLHU+LKXO2clw8xm2jjXWvTdil/u7zWmQvnlLxHolJQpRswqO4E9eJL9JYE6VJ4tRhBT+JY6W38fUk478BGKWaSGldMyAAAAAASUVORK5CYII=",
    "twitter": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEIAAABCCAYAAADjVADoAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAOkSURBVHgB7ZzfddowFIev0z70kRGcDRjBnaBkgpAJwgZ4A9IJQiaATgAbhA3EY9/aTnB7by1SImRZkq+UBPydo3ACIshfdH7WH5sCLCDiiB5uqVRUxlRK+NjsqOyprIuiePJ6B0mYUPmF54uicmse95Uh4YEeVlRGcL6UVJZ0rPXxky8i9Av3cDnM6ZgXh18K/kFPTOnhES6TG8qN9UGEgo8fiLH8pnL9SfeGKVwuX6j85Iz4BgMVixjDwLjgEysMvB5HXDKDCM0gQvM5oO4EmnNuKBWVGmThSdSs5bWSCk8VwqYJ6M8GIqH3LlEOhc3s2PY5pX49mBARzAIi4IZTecb+KCqltAQmVAQzi5TBDe0zvVfYLmGEPSQwMSL4YMaWxiyMegtLnQrj4M8sHRJ697YYEYwyG9bSoJml4TMMwyr+6O+tUIBYEcwG7N1fHdVp6z0h4TlxSHhAIfqIYGzdf2zUUejXe2zcOyTUKEhfEYxP92/rPa7wnOeSwEiIYKTDM6sERkqEQkuqY1x4uiRMMRFSIhg+6JHR8NDwfHRIiD31eiEpgmkLz+MsUHgqbISOUavlb4gjLYKJCk+HBLNXJSGFCKayHFBneL6VBCaVCOuQmJ7bGPVu34MEJpUIxhae5uSoLTx7T6JCSblCxQf4qvvTjhIv7NzA/wUeFrXClvWFrGB6astnmuOBmJGnKDlEMJXlQOdGHdupd4KZyCUiOjzxVFgScolgFMaHp8iag4ucy/lLHZYv6N+/Qnd43kFz6U86MA+PHW0wsyB7eOYQsfL4f9iyoPYQJkZqESeDqg4ZZhZkC8+UIhS6N2I26BeepYew3qQSodBvI8YnC7hul7DepBChMGwjprbUq4w6ycNTWkTsRoxPFtSWOmLhKSmiayNmGfpey3uShaekiL4bMQrtWXDci3yH6sFIiZDaiHmz8JQQIb0H4bP/sfIQFkRfEak2YnwWgGtLnSlG0kdEyo2YtvCcY5MHh9JWJ5hYETk2YhS2nIq7wIjwjBGxcjRAeiPmGSLAiPAMFdE6icJ0y++x120FhWfI5YW8ePKdCv/XzddYDje4BHk4JP/Q4xbC+QHNvWmdDNdia4YrbzWDCM0gQsMi9jCwYxE7GNiziC0MrAs9QOLbHc/57l8Xe9pour7Su013cLnU/OPfWYPvhIXmZo9Lo7Z+ewBm2nl+J7jnMNisJSg8X3gidrK+WriEQHOX8Dl8kcYemmHClsqTuSvP/AVkJTON13gofgAAAABJRU5ErkJggg==",
    "facebook": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEIAAABCCAYAAADjVADoAAABS2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDIgNzkuMTYwOTI0LCAyMDE3LzA3LzEzLTAxOjA2OjM5ICAgICAgICAiPgogPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIi8+CiA8L3JkZjpSREY+CjwveDp4bXBtZXRhPgo8P3hwYWNrZXQgZW5kPSJyIj8+nhxg7wAAAndJREFUeJztnLuKFEEUhr8uB40EL7viCwhmjohi4gaGPoD6BiY6Bi5ewMBcMdBIn0AEUwORFTYQWRYcxcBLYuywqyKI4DBlUKdlpunLyG716bbPl1VPNfXXR1UxXTPVifeeEo4A54FTwCHgQFnlBvIF+ASsAo+At0UVkwIRR4E7wOkY6RRZAZaB19kPXE7lq8Aa/58ECH1aI/RxhuyIuAdcqimUNveBQVqYHhHX6Y4ECH1dTgvpiOgD68AOpVBajIHjwDAdEXfpngSAHnAbwojok7OKdoy+A85qp2gA5xywpJ2iASwl3vsRsKCdRJlR4r2fAIl2EmUmDpMA4HrKAX4CT4BnwDtgE/hRUPcpcDJWEE0Rj4GLwGjO+uOIWdREPAQuKLWdS97TZ2w+A5cV2i1FQ8QD4JdCu6VoiFhRaLMSDRHvFdqsJPEVm5bbzG9gZ0WdW4SFdFfm+m4iLu51i/gO7KmoswnsrSHLDBpTo4raJUAzRahgIgQTIcT+iv0KODNVnmdh3ldw/SVweMuJCogtYgx8/cd7iurv32KWUtoyNXpE3kVri4gFIm8gtUXEwdgNtEXEYuwGYi+WPWa/KXrgW8U9x3Kundi2RAU08Vmjzjx/acvUiI6JEEyEYCIEEyGYCMFECCZCMBGCiRBMhGAiBBMhmAjBRAgmQjARgokQ6v4zWYLSr91V1L1n2VgcSpulDWPigA3tFA1gwwEftFM0gI+OcDi066zaUaZA3wFD4IV2EkWeA2/suGPmuOMQuKmXR40bhL7bkei0kH3WGADXiHxIRJkxoY+D6YtdfG3CFWQ6TFMkIiX7Io1F2nMYzhOOSc31Io0//E2Kh1+bj7YAAAAASUVORK5CYII=",
    "youtube": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADgAAAA4CAYAAACohjseAAAACXBIWXMAABYlAAAWJQFJUiTwAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJcSURBVHgB7ZrhUcIwGIbfoj/86QhxAmUCywY6gXUCdQJwAt1AnEA3ACYQJ7A//ScbxPejKVfuwAauTdLIc/ce0AtHX/Il35cmQOQkdQ201ilfROeUok7hl4XRnJolSfKOfRBj1ESHzxc1ojb+8ckGY9LwDUWvdYmcumaPzqsX1wzSnOLLBEUodpWMJl/LDyuDkZgrGdDkVN70KheHiMOc8FKOyaVBXcyUGeJBUXfyZhmiNCihmSIuJJWcHZmx94z4OKG+JURTxEsqBs8RLxdi0Hfp1Saqh8iJ3uAxdmNq5JMLFBOj3dBimnixrNgvEQiS2qg3i/vWtgYVAkNKMeqj7sZtxuCYhWuOwOA9SaXyUNfOxuB+K2Y3zOsa2BhcIFBML/7JIQ92ndYNciK7gkdc9OCTyaMKHnAVoor6MjlXwSGux2BGTWhyBEf4mGQUNTRhe4OW8TmLKmrcdtiGkCYyFGGr0AK+DUolMqL6bdW7u64Hm2RK3bZdyPvoQSmQUxobuFiluDQo4XhPUxKOMzjCVYjKg+VHm+q/aVwY7PswVtJ6iPo0JxyWS13HxqBCoOgtBw+q2BjMEC61i2kbg6mLqn9XTO06rGtnOwal6r9HIOhiy93qwEQiyxXYh2F5wiiHH2TMyd6Esv3CrolefiBFh/gXaSLYJ9cNkIvBT8RLnphk+YM4yXqmGJ4iTmblJPOI+Fjua1ZPG8oZUa/7CA2SozhxuGZQxuIH4jhx2C8Pxq7yoBmLA/irUpoiq576XUv05imXmByje+Qoeu7VqjVDNjP7B6HzQw31lrXhLyroqN+JpZsPAAAAAElFTkSuQmCC",
    "instagram": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEIAAABCCAYAAADjVADoAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyZpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNi1jMTQyIDc5LjE2MDkyNCwgMjAxNy8wNy8xMy0wMTowNjozOSAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTggKFdpbmRvd3MpIiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOkMxQjM0M0I2ODI1QjExRUI4NEVGRjE5MTJBQUYwMUFDIiB4bXBNTTpEb2N1bWVudElEPSJ4bXAuZGlkOkMxQjM0M0I3ODI1QjExRUI4NEVGRjE5MTJBQUYwMUFDIj4gPHhtcE1NOkRlcml2ZWRGcm9tIHN0UmVmOmluc3RhbmNlSUQ9InhtcC5paWQ6QzFCMzQzQjQ4MjVCMTFFQjg0RUZGMTkxMkFBRjAxQUMiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6QzFCMzQzQjU4MjVCMTFFQjg0RUZGMTkxMkFBRjAxQUMiLz4gPC9yZGY6RGVzY3JpcHRpb24+IDwvcmRmOlJERj4gPC94OnhtcG1ldGE+IDw/eHBhY2tldCBlbmQ9InIiPz7Mls4kAAAFsElEQVR42uxcaWxUVRS+HWhr2WpSQYFQGtA0CqJCwPgHUv8YN6wkIhoTG4P6w92IG4moccFoQlxiFGIlKuKGtmqKUkPFHySuRCIuMRaoOyVEqkhLZcbvOOfB6fG9N2/eNp15c5IvfffNvXfmnnf2e18rMpmMcaF64HKgCTgFGA9Um+Kgv4CfgN3Ah8CrwE6nzhUOjCAGrAQWAyNMaVCamXEn0OOFEQuBl4CxpjSJJOUaYL28mVKdbgLeKmEmEI0B1gG3OEnEpcylCpMMooVfxupyhBFkE3Ywt5JEpCYzyGZYqvFwAplgqckjlkRMxd9uG3uRFCJvMo0WvyTBTLAcxpIUB0tJpyZSDYq+JiecET8TI/qLKGyOig4RIzJlzTBmZIRzD3DS8yPQCwyy387XvVUCxwFTGNXFwIjfgbVAB7AV+Cfk+SkBPAs4H2gBTghr4rBUgxb8IAcnB2OS5hrgdmA5S03BGfEnsAj4oFCuD2gDxhWSESQJ5wCb1X3S5YuAMwCKXI/lJ3iM6lcrgjmK8Parz/tZwv7gGsI24G0utkg6G3gvkGRkgtF9xEeBUcAzwGAmOqK51wBj1HevCDJpEInYy0/7b26PY/WYG5NKfMGSsF94GMqZxvuNs/3Sc4IJRI9GyIR+NsaLuahCNBtYpVLq1YVQjXlCLCdHrA5XKTVoFWrSIO6f6fcLUgGe0OeivSji4Ox9hzZ958Xi/qd+3bdfRnwPHBbt0/L0NG8AVwCN7FFIr0812a2D1zkKldTo0j5d1RZ64lSNTiWqmzyOexeYpsbagcS9XYzrBpqAOqAFOCA+61JjO/0syC8j3lRfvj1H/zSwzAMDJMijLeexbrRdjVvnZ0F+9VrrYa5E6G72KpKqgPnAydz+FviIk7X/hJU9hfU3H9WLTTXWqKew26Vvh82Tvh7Ya9O3F7iB+8j+bS7z71TzPx2n1xj02I8M6m3qHvn6J4E6m/6Ubj8BPG+O7q+QRNxMxZMIYqFwJ3GhjcDXon0tsNTDuCuB60R7l8nuwEVawY2S5I+nhOj+PMbeq2xPWzEwosbh/lZxvQCYkMecdZxLyGDJjsYOJ0ZUOdz/VVzP9DFvo8NcRWcjqkKcq7oYVMPJok8S19/4mPc7ce1Un0wPJ0Y4JTpzxPUWYE8ec+4DukR7lkupcNirRrPKWO/J02v0O8xVdO7zXJM9hGbRs0Crh3EvAE+Jdj2n+sOOEV6LpCNtcoylHCnucyj/0WctHFFatMrF8IZiI/wmXaNsCjVOdJ7JnmRbKULmxznUplL8icIwbrGZ68Yc0qBtxOg4GaEDqIEc/R/irPAxZWA7XMZQrnEX8EAca/KrGjqa+y1H/wpWkXagwcP8VB3fwOl3rsNtej91QpwScbxqey2PLWQD2sb4hJlYyTHHLPYOzXkEY3qzZ0qcjDjJZDdkrbrll3ka2ksYYdBnSsLr41QN2rqbLdrtJvydb6/VqA2iPdclAYwsjmhWqtFaAEa8yLUKiy70O1GQLT/KBqeL8Jq2/DarsDpK2sbut+BbfhOBO0S7j2sOqyNWE7JLVMqbb4bunt/qlwlBJcLSUbtjAVPZQ8xhK17LEiNfeRhh/n+moc8M3Tg6zPf6zNFjAe1KHQwXcDYGSfvDOCjSx/aiyxSGFjBzaguddNFT3QSs8GuxA0S3lM12BmVCWBKhI8y1wDvAx0rMwyBSp3nABZyYTQpr4ijPWR4AfgB+4cToYI7kzCleqeGQfiInaKOj+LHlA6fCRgyU2WAOpbgYknTqJUbsKPPBfJWyCYaSSF1kLBvYuif5VabpKQ5XX0uwNNDad5Vfd1SvO1JCc7UZWkIvdcrwmnt0rvGKyb4mnE4IE5bxmo9ElrpTEl6Sp5M7L+fKPuk1gJnMrVKSjjSvaYZmgpNESJL/SIMmoD2DyiJZOB1428NOoIu9Q7dT538FGACUwCRHK00nRwAAAABJRU5ErkJggg==",
}

# Maps case.results (internal Django value) to the semantic color key in the
# email theme context — so the verdict badge always uses the user's own colors.
_RESULT_TO_COLOR_KEY = {
    "Dangerous":    "color_dangerous",
    "Suspicious":   "color_suspicious",
    "Safe":         "color_safe",
    "Inconclusive": "color_inconclusive",
    "Unchallenged": "color_inconclusive",  # closest semantic match
    "AllowListed":  "color_safe",
    "Failure":      "color_failure",
}

# Human-readable label shown in the email subject line of the verdict badge
_RESULT_LABEL = {
    "Dangerous":    "Dangerous",
    "Suspicious":   "Suspicious",
    "Safe":         "Safe",
    "Inconclusive": "Inconclusive",
    "Unchallenged": "Unchallenged",
    "AllowListed":  "Allow-listed",
    "Failure":      "Analysis failed",
}

# One-line guidance sentence per result
_RESULT_GUIDANCE = {
    "Dangerous": (
        "Do not open any files or click any links associated with this item. "
        "Contact your security team immediately if you have already interacted with it."
    ),
    "Suspicious": (
        "Exercise caution. Avoid interacting with any files or links until "
        "further investigation has been completed."
    ),
    "Safe": (
        "No threats were detected. You may proceed, but remain vigilant — "
        "no analysis is 100 % conclusive."
    ),
    "Inconclusive": (
        "Our analyzers could not reach a definitive verdict. "
        "Treat the item with caution until a human review is completed."
    ),
    "Unchallenged": (
        "The result stands as assessed. No challenge was submitted within the allowed window."
    ),
    "AllowListed": (
        "This item is on the organisation allow-list and has been cleared automatically."
    ),
    "Failure": (
        "The analysis process encountered an error. "
        "Our team has been notified and will review the case manually."
    ),
}


class FinalEmailService:

    def __init__(
        self,
        *,
        case,
        sender: str,
        recipient,
        recipient_name: str,
        profile=None,           # UserProfile — drives theme + semantic colors
    ) -> None:
        self.case          = case
        self.sender        = str(sender)
        self.recipient     = str(recipient)
        self.recipient_name = recipient_name
        self.config        = self._load_config()
        self.template      = self._load_template()
        # Resolve once — passed to render_html as **theme_ctx
        self.theme_ctx     = resolve_email_theme(profile)

    @staticmethod
    def _load_config() -> dict:
        with open(CONFIG_PATH) as f:
            return json.load(f).get("email", {})

    @staticmethod
    def _load_template():
        env = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(["html", "xml"]),
        )
        return env.get_template("final_email.jinja2")

    # ── rendering ──────────────────────────────────────────────────────────

    def render_html(self, subject: str) -> str:
        return self.template.render(
            # ── Content ───────────────────────────────────────────────────
            subject=subject,
            recipient_name=self.recipient_name,
            company_name=self.config.get("content", {}).get("team_name"),
            company_logo=resolve_logo(self.config.get("logos", {}).get("company")),
            final_logo=resolve_logo(self.config.get("logos", {}).get("suspicious")),
            portal_url=self.config.get("links", {}).get("submissions"),
            glossary_url=self.config.get("links", {}).get("glossary"),
            inquiry_url=self.config.get("links", {}).get("inquiry"),
            inquiry_text=self.config.get("links", {}).get("inquiry_text"),
            global_team=self.config.get("content", {}).get("global_domain"),
            global_url=self.config.get("content", {}).get("website"),
            socials=[
                FinalMailServiceConfigSocial(
                    name=s,
                    url=self.config.get("socials", {}).get(s, f"https://{s}.com"),
                    logo=SOCIAL_LOGOS.get(s),
                )
                for s in self.config.get("socials", {})
                if SOCIAL_LOGOS.get(s)
            ],
            # ── Case metadata ─────────────────────────────────────────────
            case=self._build_case_context(),
            # ── Theme (all palette + semantic color vars) ──────────────────
            **self.theme_ctx,
        )

    # ── case helpers ───────────────────────────────────────────────────────

    def _build_case_context(self) -> dict:
        """
        Merge artifact metadata with verdict data into a single dict
        that the template can use without any logic.
        """
        meta    = self._case_metadata()
        verdict = self._verdict_context()
        return {**meta, **verdict}

    def _case_metadata(self) -> dict:
        fom = getattr(self.case, "fileOrMail", None)

        if fom and getattr(fom, "mail", None):
            mail = fom.mail
            return {
                "type":      "Email",
                "subject":   getattr(mail, "subject", ""),
                "sender":    getattr(mail, "mail_from", ""),
                "recipient": getattr(mail, "to", None),
            }

        if fom and getattr(fom, "file", None):
            file_field = getattr(fom.file, "file_path", None)
            file_name  = getattr(file_field, "name", None) or str(fom.file_id)
            return {
                "type":      "File",
                "subject":   file_name,
                "sender":    None,
                "recipient": None,
            }

        ioc = getattr(self.case, "nonFileIocs", None)
        if ioc:
            if getattr(ioc, "url", None):
                kind  = "URL"
                value = getattr(ioc.url, "address", str(ioc.url_id))
            elif getattr(ioc, "ip", None):
                kind  = "IP address"
                value = getattr(ioc.ip, "address", str(ioc.ip_id))
            elif getattr(ioc, "hash", None):
                kind  = "Hash"
                value = getattr(ioc.hash, "value", str(ioc.hash_id))
            else:
                kind  = "Indicator"
                value = str(self.case.id)
            return {
                "type":      kind,
                "subject":   value,
                "sender":    None,
                "recipient": None,
            }

        return {
            "type":      "Submission",
            "subject":   str(self.case.id),
            "sender":    None,
            "recipient": None,
        }

    def _verdict_context(self) -> dict:
        """
        Build verdict fields that reference theme color keys by name
        rather than hardcoding hex values.  The template resolves the
        actual color through the theme_ctx variables.
        """
        raw_result = getattr(self.case, "results", None) or "Failure"

        return {
            # The internal result string e.g. "Dangerous", "Safe"
            "result":       raw_result,
            # The CSS variable name in the theme context that holds this
            # result's color — e.g. "color_dangerous", "color_safe"
            # Template uses: style="color:{{ case.result_color_var | theme_color }}"
            # We just pass the name; template does: {{ theme_color_for(case.result) }}
            # Simpler: pass the resolved hex directly so template stays logic-free.
            "result_color": self.theme_ctx.get(
                _RESULT_TO_COLOR_KEY.get(raw_result, "color_inconclusive"),
                "#94A3B8",
            ),
            "result_label": _RESULT_LABEL.get(raw_result, raw_result),
            "result_guidance": _RESULT_GUIDANCE.get(
                raw_result,
                "Please review the case details on the portal."
            ),
            # AI fields — shown as reference chips
            "result_ai":        getattr(self.case, "resultsAI",  None),
            "category_ai":      getattr(self.case, "categoryAI", None),
            "score":            getattr(self.case, "finalScore",      None),
            "confidence":       getattr(self.case, "finalConfidence", None),
            # Challenge URL — empty string if not available
            "challenge_url":    self._challenge_url(),
        }

    def _challenge_url(self) -> str:
        try:
            api_base = self.config.get("api_base", None)
            if not api_base:
                parsed = urlparse(self.config.get("links", {}).get("submissions", ""))
                if parsed.scheme and parsed.netloc:
                    api_base = f"{parsed.scheme}://{parsed.netloc}"
            if not api_base:
                return ""
            token, _ = CaseChallengeToken.issue_token(self.case)
            return CaseChallengeToken.build_challenge_url(self.case.id, token, api_base)
        except Exception:
            return ""

    # ── send ───────────────────────────────────────────────────────────────

    def _send_action(self, user: str, subject: str) -> None:
        html = self.render_html(subject=subject)

        smtp = self.config.get("smtp", {})
        send_mail_service = SendMailService(
            host=smtp.get("server", ""),
            port=smtp.get("port", 587),
            login=smtp.get("username", ""),
            password=smtp.get("password", ""),
        )

        send_mail_service.connect()
        if smtp.get("tls"):
            send_mail_service.start_tls()
        send_mail_service.login()
        send_mail_service.publish_email(
            subject=subject,
            sender=self.sender,
            recipient=user,
            html=html,
        )
        send_mail_service.close()
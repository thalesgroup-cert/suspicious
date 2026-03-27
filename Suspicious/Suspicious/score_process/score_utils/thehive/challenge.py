import json
import logging

from thehive4py import TheHiveApi
from minio import Minio
from minio.error import S3Error
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
from mail_feeder.models import MailArtifact, MailAttachment

from .utils import generate_ref, build_mail_attachments_paths

logger = logging.getLogger(__name__)
update_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")
TEMPLATES_DIR = Path(__file__).parent.parent / "send_mail/templates"


CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)
minio_config = config.get("storage", {}).get("minio", {})
thehive_config = config.get('integrations', {}).get('thehive', {})

SOCIAL_LOGOS = {
    "linkedin": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEIAAABCCAYAAADjVADoAAABS2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDIgNzkuMTYwOTI0LCAyMDE3LzA3LzEzLTAxOjA2OjM5ICAgICAgICAiPgogPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIi8+CiA8L3JkZjpSREY+CjwveDp4bXBtZXRhPgo8P3hwYWNrZXQgZW5kPSJyIj8+nhxg7wAAA09JREFUeJzt3EuoHEUUxvHftEJEiVcwiigE34oomQtXBI0xiojgUlH3rlyYhUIkoCCIm5gs1IVuVQTFTdyKRBME8YU3vsDHIosEhGuUCC4kyS0XVa2TsacncWrSfdP9h15M1Zk+p7853VNV3acHIQQ1LOJh3IVrcUmdcQtZwc/Yh3ewPMlwMEGIRezG3fOIrkE+wpP4aryjqDDejs+cfSLAVvHYto93jGbEAC/hiTMWVrO8gm3lh9GM2KE7IhCP9Z/MKDNiEZ/jnIaCaooTWMJymRG7dU8E4jG/SMyIoYqraMcYFuI4oes8UmBL01G0gC2DEMIKNjQdScOsDEIIq+IYosusFnoRoKgaYneSczPv7xj24zCux23WSMblFOIAHhKnvSW3411cntHPXBiEKQsSp8hR3IhfKvqW8KnqmW5ryBXcG6pFgC/EhZFWk0uI76f0f5vJz9zIJcS0AVnrB2y5rhHfYIjVir4FHMRFGfzMjVwZcQt2+u9f5Tq8qeUikC8jSvbhdRzCDXgcN2Xc/9zILcSapdX/7WeSnCPLPeIQe5zz8cBY24f4tcJ2g39vIxzFa3gP3+EPrMfVuF9cfL1i5qhLQj4WQggqto0Vtpsn2G5O/XtCCBdPsCm3dSGEnbmCb+Op8RYexJEpdn+Jy/HP5nDaNiEO4jFxmf1UeQGfzOq4bUIcEn/p0yHg+Vkdt02I/8v7+H2WHbRViGvwqpjyH+M5XFBjfwJfzuIw9wpVDjaJI9SFkbY70nafeCpUcXgWp23MiF1OFqHkXvWPKvw2i9O2CbEe99T01/Wd7kX2JNomxFXqY9o4L8dtE+LCKf1zu2PfNiEaoxci0QuR6IVI9EIkeiESvRCJXohEL0SiFyKRcxq+FX9WtF9a0baE8yrab57i4zJxFlrFlVO+W0t/gyfRnxqJXohEL0SiFyLRC5EoTF4V7hKrhen3GLvAkQI/NB1FC/ixEB8Z7jr7+1KmyLAQy4T3Nh1Jg3yAA2W541B8VLhrlX7HcauRcsdlPNNcPI2xQyqcHy+Sf1l3qoEnlkRLHU+LKXO2clw8xm2jjXWvTdil/u7zWmQvnlLxHolJQpRswqO4E9eJL9JYE6VJ4tRhBT+JY6W38fUk478BGKWaSGldMyAAAAAASUVORK5CYII=",
    "twitter": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEIAAABCCAYAAADjVADoAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAOkSURBVHgB7ZzfddowFIev0z70kRGcDRjBnaBkgpAJwgZ4A9IJQiaATgAbhA3EY9/aTnB7by1SImRZkq+UBPydo3ACIshfdH7WH5sCLCDiiB5uqVRUxlRK+NjsqOyprIuiePJ6B0mYUPmF54uicmse95Uh4YEeVlRGcL6UVJZ0rPXxky8i9Av3cDnM6ZgXh18K/kFPTOnhES6TG8qN9UGEgo8fiLH8pnL9SfeGKVwuX6j85Iz4BgMVixjDwLjgEysMvB5HXDKDCM0gQvM5oO4EmnNuKBWVGmThSdSs5bWSCk8VwqYJ6M8GIqH3LlEOhc3s2PY5pX49mBARzAIi4IZTecb+KCqltAQmVAQzi5TBDe0zvVfYLmGEPSQwMSL4YMaWxiyMegtLnQrj4M8sHRJ697YYEYwyG9bSoJml4TMMwyr+6O+tUIBYEcwG7N1fHdVp6z0h4TlxSHhAIfqIYGzdf2zUUejXe2zcOyTUKEhfEYxP92/rPa7wnOeSwEiIYKTDM6sERkqEQkuqY1x4uiRMMRFSIhg+6JHR8NDwfHRIiD31eiEpgmkLz+MsUHgqbISOUavlb4gjLYKJCk+HBLNXJSGFCKayHFBneL6VBCaVCOuQmJ7bGPVu34MEJpUIxhae5uSoLTx7T6JCSblCxQf4qvvTjhIv7NzA/wUeFrXClvWFrGB6astnmuOBmJGnKDlEMJXlQOdGHdupd4KZyCUiOjzxVFgScolgFMaHp8iag4ucy/lLHZYv6N+/Qnd43kFz6U86MA+PHW0wsyB7eOYQsfL4f9iyoPYQJkZqESeDqg4ZZhZkC8+UIhS6N2I26BeepYew3qQSodBvI8YnC7hul7DepBChMGwjprbUq4w6ycNTWkTsRoxPFtSWOmLhKSmiayNmGfpey3uShaekiL4bMQrtWXDci3yH6sFIiZDaiHmz8JQQIb0H4bP/sfIQFkRfEak2YnwWgGtLnSlG0kdEyo2YtvCcY5MHh9JWJ5hYETk2YhS2nIq7wIjwjBGxcjRAeiPmGSLAiPAMFdE6icJ0y++x120FhWfI5YW8ePKdCv/XzddYDje4BHk4JP/Q4xbC+QHNvWmdDNdia4YrbzWDCM0gQsMi9jCwYxE7GNiziC0MrAs9QOLbHc/57l8Xe9pour7Su013cLnU/OPfWYPvhIXmZo9Lo7Z+ewBm2nl+J7jnMNisJSg8X3gidrK+WriEQHOX8Dl8kcYemmHClsqTuSvP/AVkJTON13gofgAAAABJRU5ErkJggg==",
    "facebook": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEIAAABCCAYAAADjVADoAAABS2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDIgNzkuMTYwOTI0LCAyMDE3LzA3LzEzLTAxOjA2OjM5ICAgICAgICAiPgogPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIi8+CiA8L3JkZjpSREY+CjwveDp4bXBtZXRhPgo8P3hwYWNrZXQgZW5kPSJyIj8+nhxg7wAAAndJREFUeJztnLuKFEEUhr8uB40EL7viCwhmjohi4gaGPoD6BiY6Bi5ewMBcMdBIn0AEUwORFTYQWRYcxcBLYuywqyKI4DBlUKdlpunLyG716bbPl1VPNfXXR1UxXTPVifeeEo4A54FTwCHgQFnlBvIF+ASsAo+At0UVkwIRR4E7wOkY6RRZAZaB19kPXE7lq8Aa/58ECH1aI/RxhuyIuAdcqimUNveBQVqYHhHX6Y4ECH1dTgvpiOgD68AOpVBajIHjwDAdEXfpngSAHnAbwojok7OKdoy+A85qp2gA5xywpJ2iASwl3vsRsKCdRJlR4r2fAIl2EmUmDpMA4HrKAX4CT4BnwDtgE/hRUPcpcDJWEE0Rj4GLwGjO+uOIWdREPAQuKLWdS97TZ2w+A5cV2i1FQ8QD4JdCu6VoiFhRaLMSDRHvFdqsJPEVm5bbzG9gZ0WdW4SFdFfm+m4iLu51i/gO7KmoswnsrSHLDBpTo4raJUAzRahgIgQTIcT+iv0KODNVnmdh3ldw/SVweMuJCogtYgx8/cd7iurv32KWUtoyNXpE3kVri4gFIm8gtUXEwdgNtEXEYuwGYi+WPWa/KXrgW8U9x3Kundi2RAU08Vmjzjx/acvUiI6JEEyEYCIEEyGYCMFECCZCMBGCiRBMhGAiBBMhmAjBRAgmQjARgokQ6v4zWYLSr91V1L1n2VgcSpulDWPigA3tFA1gwwEftFM0gI+OcDi066zaUaZA3wFD4IV2EkWeA2/suGPmuOMQuKmXR40bhL7bkei0kH3WGADXiHxIRJkxoY+D6YtdfG3CFWQ6TFMkIiX7Io1F2nMYzhOOSc31Io0//E2Kh1+bj7YAAAAASUVORK5CYII=",
    "youtube": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADgAAAA4CAYAAACohjseAAAACXBIWXMAABYlAAAWJQFJUiTwAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJcSURBVHgB7ZrhUcIwGIbfoj/86QhxAmUCywY6gXUCdQJwAt1AnEA3ACYQJ7A//ScbxPejKVfuwAauTdLIc/ce0AtHX/Il35cmQOQkdQ201ilfROeUok7hl4XRnJolSfKOfRBj1ESHzxc1ojb+8ckGY9LwDUWvdYmcumaPzqsX1wzSnOLLBEUodpWMJl/LDyuDkZgrGdDkVN70KheHiMOc8FKOyaVBXcyUGeJBUXfyZhmiNCihmSIuJJWcHZmx94z4OKG+JURTxEsqBs8RLxdi0Hfp1Saqh8iJ3uAxdmNq5JMLFBOj3dBimnixrNgvEQiS2qg3i/vWtgYVAkNKMeqj7sZtxuCYhWuOwOA9SaXyUNfOxuB+K2Y3zOsa2BhcIFBML/7JIQ92ndYNciK7gkdc9OCTyaMKHnAVoor6MjlXwSGux2BGTWhyBEf4mGQUNTRhe4OW8TmLKmrcdtiGkCYyFGGr0AK+DUolMqL6bdW7u64Hm2RK3bZdyPvoQSmQUxobuFiluDQo4XhPUxKOMzjCVYjKg+VHm+q/aVwY7PswVtJ6iPo0JxyWS13HxqBCoOgtBw+q2BjMEC61i2kbg6mLqn9XTO06rGtnOwal6r9HIOhiy93qwEQiyxXYh2F5wiiHH2TMyd6Esv3CrolefiBFh/gXaSLYJ9cNkIvBT8RLnphk+YM4yXqmGJ4iTmblJPOI+Fjua1ZPG8oZUa/7CA2SozhxuGZQxuIH4jhx2C8Pxq7yoBmLA/irUpoiq576XUv05imXmByje+Qoeu7VqjVDNjP7B6HzQw31lrXhLyroqN+JpZsPAAAAAElFTkSuQmCC",
    "instagram": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEIAAABCCAYAAADjVADoAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyZpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNi1jMTQyIDc5LjE2MDkyNCwgMjAxNy8wNy8xMy0wMTowNjozOSAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTggKFdpbmRvd3MpIiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOkMxQjM0M0I2ODI1QjExRUI4NEVGRjE5MTJBQUYwMUFDIiB4bXBNTTpEb2N1bWVudElEPSJ4bXAuZGlkOkMxQjM0M0I3ODI1QjExRUI4NEVGRjE5MTJBQUYwMUFDIj4gPHhtcE1NOkRlcml2ZWRGcm9tIHN0UmVmOmluc3RhbmNlSUQ9InhtcC5paWQ6QzFCMzQzQjQ4MjVCMTFFQjg0RUZGMTkxMkFBRjAxQUMiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6QzFCMzQzQjU4MjVCMTFFQjg0RUZGMTkxMkFBRjAxQUMiLz4gPC9yZGY6RGVzY3JpcHRpb24+IDwvcmRmOlJERj4gPC94OnhtcG1ldGE+IDw/eHBhY2tldCBlbmQ9InIiPz7Mls4kAAAFsElEQVR42uxcaWxUVRS+HWhr2WpSQYFQGtA0CqJCwPgHUv8YN6wkIhoTG4P6w92IG4moccFoQlxiFGIlKuKGtmqKUkPFHySuRCIuMRaoOyVEqkhLZcbvOOfB6fG9N2/eNp15c5IvfffNvXfmnnf2e18rMpmMcaF64HKgCTgFGA9Um+Kgv4CfgN3Ah8CrwE6nzhUOjCAGrAQWAyNMaVCamXEn0OOFEQuBl4CxpjSJJOUaYL28mVKdbgLeKmEmEI0B1gG3OEnEpcylCpMMooVfxupyhBFkE3Ywt5JEpCYzyGZYqvFwAplgqckjlkRMxd9uG3uRFCJvMo0WvyTBTLAcxpIUB0tJpyZSDYq+JiecET8TI/qLKGyOig4RIzJlzTBmZIRzD3DS8yPQCwyy387XvVUCxwFTGNXFwIjfgbVAB7AV+Cfk+SkBPAs4H2gBTghr4rBUgxb8IAcnB2OS5hrgdmA5S03BGfEnsAj4oFCuD2gDxhWSESQJ5wCb1X3S5YuAMwCKXI/lJ3iM6lcrgjmK8Parz/tZwv7gGsI24G0utkg6G3gvkGRkgtF9xEeBUcAzwGAmOqK51wBj1HevCDJpEInYy0/7b26PY/WYG5NKfMGSsF94GMqZxvuNs/3Sc4IJRI9GyIR+NsaLuahCNBtYpVLq1YVQjXlCLCdHrA5XKTVoFWrSIO6f6fcLUgGe0OeivSji4Ox9hzZ958Xi/qd+3bdfRnwPHBbt0/L0NG8AVwCN7FFIr0812a2D1zkKldTo0j5d1RZ64lSNTiWqmzyOexeYpsbagcS9XYzrBpqAOqAFOCA+61JjO/0syC8j3lRfvj1H/zSwzAMDJMijLeexbrRdjVvnZ0F+9VrrYa5E6G72KpKqgPnAydz+FviIk7X/hJU9hfU3H9WLTTXWqKew26Vvh82Tvh7Ya9O3F7iB+8j+bS7z71TzPx2n1xj02I8M6m3qHvn6J4E6m/6Ubj8BPG+O7q+QRNxMxZMIYqFwJ3GhjcDXon0tsNTDuCuB60R7l8nuwEVawY2S5I+nhOj+PMbeq2xPWzEwosbh/lZxvQCYkMecdZxLyGDJjsYOJ0ZUOdz/VVzP9DFvo8NcRWcjqkKcq7oYVMPJok8S19/4mPc7ce1Un0wPJ0Y4JTpzxPUWYE8ec+4DukR7lkupcNirRrPKWO/J02v0O8xVdO7zXJM9hGbRs0Crh3EvAE+Jdj2n+sOOEV6LpCNtcoylHCnucyj/0WctHFFatMrF8IZiI/wmXaNsCjVOdJ7JnmRbKULmxznUplL8icIwbrGZ68Yc0qBtxOg4GaEDqIEc/R/irPAxZWA7XMZQrnEX8EAca/KrGjqa+y1H/wpWkXagwcP8VB3fwOl3rsNtej91QpwScbxqey2PLWQD2sb4hJlYyTHHLPYOzXkEY3qzZ0qcjDjJZDdkrbrll3ka2ksYYdBnSsLr41QN2rqbLdrtJvydb6/VqA2iPdclAYwsjmhWqtFaAEa8yLUKiy70O1GQLT/KBqeL8Jq2/DarsDpK2sbut+BbfhOBO0S7j2sOqyNWE7JLVMqbb4bunt/qlwlBJcLSUbtjAVPZQ8xhK17LEiNfeRhh/n+moc8M3Tg6zPf6zNFjAe1KHQwXcDYGSfvDOCjSx/aiyxSGFjBzaguddNFT3QSs8GuxA0S3lM12BmVCWBKhI8y1wDvAx0rMwyBSp3nABZyYTQpr4ijPWR4AfgB+4cToYI7kzCleqeGQfiInaKOj+LHlA6fCRgyU2WAOpbgYknTqJUbsKPPBfJWyCYaSSF1kLBvYuif5VabpKQ5XX0uwNNDad5Vfd1SvO1JCc7UZWkIvdcrwmnt0rvGKyb4mnE4IE5bxmo9ElrpTEl6Sp5M7L+fKPuk1gJnMrVKSjjSvaYZmgpNESJL/SIMmoD2DyiJZOB1428NOoIu9Q7dT538FGACUwCRHK00nRwAAAABJRU5ErkJggg==",
}
class ChallengeToTheHiveService:
    def __init__(self, case, recipient, subject):
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)

        self.case = case
        self.challenger = case.reporter
        self.challenger_firstname = case.reporter.first_name
        self.challenger_lastname = case.reporter.last_name
        self.challenger_email = case.reporter.email
        self.challenger_groups = [g.name for g in case.reporter.groups.all()]
        self.recipient = recipient
        self.subject = subject

        self.template = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(["html"])
        ).get_template("challenge_email.jinja2")

    def _context(self) -> dict:
        mail = getattr(getattr(self.case, "fileOrMail", None), "mail", None)

        artifacts = [
            {
                "label": a.artifact_type,
                "score": a.artifact_score,
                "confidence": a.artifact_confidence,
            }
            for a in MailArtifact.objects.filter(mail=mail)
        ]

        attachments = [
            a.file.file_path.name
            for a in MailAttachment.objects.filter(mail=mail)
        ]

        result_color = {
            "Dangerous": "#EF3340",
            "Suspicious": "#FFAA4D",
            "Safe": "#00AB84",
            "Inconclusive": "#0085CA",
        }.get(self.case.results, "#000")

        mail_cfg = self.config.get('email', {})

        return {
            "subject": self.subject,
            "recipient_name": self.recipient,
            "company": mail_cfg.get("content", {}).get("team_name"),
            "global_team": mail_cfg.get("content", {}).get("global_domain"),
            "logos": mail_cfg.get("logos", {}),
            "urls": {
                "portal": mail_cfg.get("links", {}).get("submissions"),
                "glossary": mail_cfg.get("links", {}).get("glossary"),
                "inquiry": mail_cfg.get("links", {}).get("inquiry"),
                "global": mail_cfg.get("content", {}).get("website"),
            },
            "inquiry_text": mail_cfg.get("links", {}).get("inquiry_text"),
            "socials": [
                {
                    "name": social,
                    "url": self.config.get("socials", {}).get(
                        social, f"https://{social}.com"
                    ),
                    "logo": SOCIAL_LOGOS.get(social),
                }
                for social in mail_cfg.get("socials", {})
                if SOCIAL_LOGOS.get(social)
            ],
            "challenger": {
                "firstname": self.challenger.first_name,
                "lastname": self.challenger.last_name,
                "email": self.challenger.email,
                "groups": ", ".join(
                    g.name for g in self.challenger.groups.all()
                ) or "No group",
            },
            "case": {
                "id": self.case.id,
                "score": self.case.score,
                "confidence": self.case.confidence,
                "result": self.case.results,
                "result_color": result_color,
                "ai": {
                    "category": self.case.categoryAI,
                    "result": self.case.resultsAI,
                    "score": round(self.case.scoreAI),
                    "confidence": round(self.case.confidenceAI),
                },
            },
            "mail": {
                "subject": getattr(mail, "subject", "N/A"),
                "from": getattr(mail, "mail_from", "N/A"),
            },
            "artifacts": artifacts,
            "attachments": attachments,
        }

    def send(self) -> None:
        html = self.template.render(self._context())

        msg = MIMEMultipart("alternative")
        msg["From"] = self.config["mail"]["username"]
        msg["To"] = self.recipient
        msg["Subject"] = self.subject
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(
            self.config["mail"]["server"],
            self.config["mail"]["port"]
        ) as smtp:
            smtp.send_message(msg)


    def send_to_thehive(self):
        """
        Send an alert to TheHive from a challenge.

        Creates an alert in TheHive with the details of the challenge,
        including case, mail, challenger info, and related artifacts/attachments.
        """
        def safe(value, default=None):
            return value if value not in (None, "") else default

        # Challenger information
        challenger = {
            "firstname": safe(self.challenger_firstname),
            "lastname": safe(self.challenger_lastname),
            "email": safe(self.challenger_email),
            "groups": safe(self.challenger_groups, [])
        }

        case = self.case
        mail = getattr(getattr(case, "fileOrMail", None), "mail", None)

        # TheHive connection parameters
        THE_HIVE_URL = thehive_config.get("url", "")
        THE_HIVE_KEY = thehive_config.get("api_key", "")


        if not mail:
            fileormail = case.fileOrMail
            if fileormail:
                file = fileormail.file
                if file:
                  create_alert_from_challenge_without_mail(
                      api_url=THE_HIVE_URL,
                      api_key=THE_HIVE_KEY,
                      case=case,
                      file=file,
                      ioc=file.linked_hash.value,
                      datatype="hash",
                      challenger=challenger
                  )
            else:
              nonfileiocs = case.nonFileIocs
              if nonfileiocs:
                  url = nonfileiocs.url
                  ip = nonfileiocs.ip
                  hash = nonfileiocs.hash

                  if url:
                      create_alert_from_challenge_without_mail(
                          api_url=THE_HIVE_URL,
                          api_key=THE_HIVE_KEY,
                          case=case,
                          file=None,
                          ioc=url.address,
                          datatype="url",
                          challenger=challenger
                      )
                  if ip:
                      create_alert_from_challenge_without_mail(
                          api_url=THE_HIVE_URL,
                          api_key=THE_HIVE_KEY,
                          case=case,
                          file=None,
                          ioc=ip.address,
                          datatype="ip",
                          challenger=challenger
                      )
                  if hash:
                      create_alert_from_challenge_without_mail(
                          api_url=THE_HIVE_URL,
                          api_key=THE_HIVE_KEY,
                          case=case,
                          file=None,
                          ioc=hash.value,
                          datatype="hash",
                          challenger=challenger
                      )
            return  # Exit if there's no mail associated with the case
        # Prepare artifacts mapping
        artifact_type_map = {
            "ip": lambda a: (safe(getattr(getattr(a, "artifactIsIp", None), "ip.address", None)), "ip"),
            "url": lambda a: (safe(getattr(getattr(a, "artifactIsUrl", None), "url.address", None)), "url"),
            "mailaddress": lambda a: (safe(getattr(getattr(a, "artifactIsMailAddress", None), "mail_address.address", None)), "mail"),
            "domain": lambda a: (safe(getattr(getattr(a, "artifactIsDomain", None), "domain.value", None)), "domain"),
            "hash": lambda a: (safe(getattr(getattr(a, "artifactIsHash", None), "hash.value", None)), "hash")
        }

        artifact_summary = []
        for artifact in MailArtifact.objects.filter(mail=mail):
            if artifact:
                artifact_type = safe(artifact.artifact_type, "").lower()
                if artifact_type in artifact_type_map:
                    data, dtype = artifact_type_map[artifact_type](artifact)
                    if data:  # Only add non-empty data
                        artifact_summary.append((data, dtype))

        # Prepare attachments
        attachments_summary = [
            safe(att.file.file_path.name)
            for att in MailAttachment.objects.filter(mail=mail)
            if safe(att.file.file_path.name)
        ]

        # Send alert to TheHive
        try:
            create_alert_from_challenge(
                api_url=THE_HIVE_URL,
                api_key=THE_HIVE_KEY,
                case=case,
                mail=mail,
                challenger=challenger,
                artifact_summary=artifact_summary,
                attachments_summary=attachments_summary
            )
        except Exception as e:
            # You might want to use logging instead of print in production
            print(f"[ERROR] Failed to create TheHive alert for case #{safe(case.id)}: {e}")

def create_alert_from_challenge_without_mail(api_url, api_key, case, file, ioc, datatype, challenger):
    """
    Create an alert in TheHive when a user challenges the result of a case.

    :param api_url: TheHive API base URL
    :param api_key: TheHive API key
    :param case: Case object containing analysis results
    :param file: File object related to the case
    :param ioc: IOC object related to the case
    :param challenger: dict with keys 'firstname', 'lastname', 'email'
    :param artifact_summary: list of tuples (value, type) for extracted artifacts
    :param attachments_summary: list of filenames for attachments
    """
    api = TheHiveApi(url=api_url, apikey=api_key, verify=thehive_config.get('verify_ssl', ''))
    ticket_id = generate_ref()
    # Construction du titre
    if file:
      title = f"Challenge: Case #{case.id} - File {file.file_path.name}"
    else:
      title = f"Challenge: Case #{case.id} - IOC {str(ioc)} ({datatype})"
    # Description complète
    description = (
        f"# {challenger.get('firstname', 'N/A')} {challenger.get('lastname', 'N/A')} "
        f"({challenger.get('email', 'N/A')}) has challenged the result of case #{case.id}.\n\n"
        f"|Value|Description|\n"
        f"|---|---|\n"
        f"|Case Score|{getattr(case, 'score', 'N/A')}|\n"
        f"|Case Confidence|{getattr(case, 'confidence', 'N/A')}|\n"
        f"|Results|{getattr(case, 'results', 'N/A')}|"
    )
    # Création des observables
    observables = [
        {"data": ioc, "dataType": datatype}
    ]
    # Envoi de l'alerte
    return api.alert.create(
        alert={
            "type": "user_challenge",
            "source": "suspicious",
            "sourceRef": ticket_id,
            "title": title,
            "description": description,
            "observables": observables,
            "severity": 1,  # 1=Low, 2=Medium, 3=High
            "tlp": 1,
            "pap": 1,
            "tags": ["challenge", "file_ioc", "suspicious"],
            "customFields": {
                "tha-id": ticket_id
            }
        }
    )

def create_alert_from_challenge(api_url, api_key, case, mail, challenger, artifact_summary=None, attachments_summary=None):
    """
    Create an alert in TheHive when a user challenges the result of a case.

    :param api_url: TheHive API base URL
    :param api_key: TheHive API key
    :param case: Case object containing analysis results
    :param mail: Mail object related to the case
    :param challenger: dict with keys 'firstname', 'lastname', 'email'
    :param artifact_summary: list of tuples (value, type) for extracted artifacts
    :param attachments_summary: list of filenames for attachments
    """
    api = TheHiveApi(url=api_url, apikey=api_key, verify=thehive_config.get('verify_ssl', ''))
    eml = ""
    # Utilitaires pour gérer les valeurs None
    def safe(value, default="N/A"):
        return value if value not in (None, "") else default
    ticket_id = generate_ref()
    # Construction du titre
    title = f"Challenge: Case #{safe(case.id)} - {safe(getattr(mail, 'subject', None), 'No Subject')}"

    # Tableau récapitulatif
    summary_table = f"""|Value|Description|
|---|---|
|Mail Subject|{safe(getattr(mail, 'subject', None))}|
|From|{safe(getattr(mail, 'mail_from', None))}|
|Case Score|{safe(getattr(case, 'score', None))}|
|Case Confidence|{safe(getattr(case, 'confidence', None))}|
|AI Suggestion|{safe(getattr(case, 'categoryAI', None))} / {safe(getattr(case, 'resultsAI', None))} (Score: {round(getattr(case, 'scoreAI', 0))}, Confidence: {round(getattr(case, 'confidenceAI', 0))})|
|Results|{safe(getattr(case, 'results', None))}|"""

    # Liste des artefacts
    artifacts_section = "\n".join(
        f"- {val[0].replace('.', '[.]')} ({val[1]})" for val in (artifact_summary or [])
    ) or "No artifacts found."

    # Liste des pièces jointes
    attachments_section = "\n".join(
        f"- {val}" for val in (attachments_summary or [])
    ) or "No attachments found."

    # Description complète
    description = (
        f"# {safe(challenger.get('firstname'))} {safe(challenger.get('lastname'))} "
        f"({safe(challenger.get('email'))}) has challenged the result of case #{safe(case.id)}.\n\n"
        f"{summary_table}\n\n"
        f"## Extracted Artifacts:\n{artifacts_section}\n\n"
        f"## Attachments:\n{attachments_section}"
    )
    mail_id = safe(getattr(mail, 'mail_id', None), 'unknown-mail-id')
    minio_client = Minio(
        minio_config.get("endpoint"),
        access_key=minio_config.get("access_key"),
        secret_key=minio_config.get("secret_key"),
        secure=minio_config.get("secure", False)
    )
    for bucket in minio_client.list_buckets():
        if bucket.name.endswith(f"-{mail_id.split('-')[0]}"):
            try:
                objects = minio_client.list_objects(bucket.name, prefix=mail_id, recursive=False)
                for obj in objects:
                    if obj.object_name.startswith(mail_id):
                        expected_eml_key = f"{mail_id}/{mail_id}.eml"
                        data = minio_client.get_object(bucket.name, expected_eml_key)
                        eml = data.read().decode('utf-8')
            except S3Error as e:
                print(f"Error listing objects in bucket {bucket.name}: {e}")
    tmp_path = build_mail_attachments_paths(eml, ticket_id)
    
    attachment_key = ticket_id
    attachment_map = {attachment_key: tmp_path}
    # Création des observables
    observables = [
        {"data": val[0], "dataType": val[1]}
        for val in (artifact_summary or [])
    ] + [
        {"dataType": "file", "attachment": attachment_key} if tmp_path else {}
    ]
    # Envoi de l'alerte
    return api.alert.create(
        alert={
            "type": "user_challenge",
            "source": "suspicious",
            "sourceRef": ticket_id,
            "title": title,
            "description": description,
            "observables": observables,
            "severity": 1,  # 1=Low, 2=Medium, 3=High
            "tlp": 1,
            "pap": 1,
            "tags": ["challenge", "mail", "suspicious"],
            "customFields": {
                "tha-id": ticket_id
            }
        }, attachment_map=attachment_map
    )

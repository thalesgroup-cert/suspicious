import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
from pathlib import Path

CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

mail_config = config.get('mail', {})

class AcknowledgementEmail:
    """Class to create and send an HTML email for submission acknowledgment."""

    def __init__(self, subject, sender, recipient, infos):
        self.subject = subject
        self.sender = sender
        self.recipient = recipient
        self.infos = infos

    def _html_header(self):
        return """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Suspicious: Submission Registered</title>
    <style type="text/css">
      /* Reset and base styles */
      html, body {
        margin: 0 auto;
        padding: 0;
        min-width: 260px;
        width: 100% !important;
        height: 100% !important;
      }

      a img {
        border: none;
      }

      table, td {
        border-collapse: collapse;
        mso-table-lspace: 0pt;
        mso-table-rspace: 0pt;
      }

      .ReadMsgBody, .ExternalClass {
        width: 100%;
      }

      .ExternalClass * {
        line-height: 100%;
      }

      ul {
        padding: 0 !important;
        margin: 0 0 0 40px !important;
      }

      li {
        margin-bottom: 10px !important;
      }

      a {
        color: #00BBDD;
        text-decoration: none;
      }

      .button {
        word-wrap: break-word;
      }

      sub, sup {
        font-size: 70%;
        line-height: 0;
        position: relative;
      }

      sup {
        mso-text-raise: 60%;
        vertical-align: super;
      }

      sub {
        bottom: -0.25em;
      }

      /* Responsive styles */
      @media screen and (max-width: 520px) {
        .tolkien-column {
          width: 100% !important;
          max-width: 100% !important;
          min-width: auto !important;
        }

        .tolkien-column img.full {
          width: 100% !important;
          max-width: 100% !important;
        }

        .tolkien-column img[shrinktofit=true] {
          width: auto !important;
          max-width: 100% !important;
        }

        .hide-in-mobile {
          display: none !important;
          max-height: 0px !important;
          overflow: hidden !important;
          font-size: 0px !important;
        }

        .hide-in-desktop {
          display: block !important;
          max-height: none !important;
        }
      }

      /* Optional image-specific overrides */
      @media screen and (max-width: 767px) {
        .row-0 .col-0 .cell-0 img {
          width: min(100%, 100px) !important;
        }

        .row-0 .col-1 .cell-1 img {
          width: min(100%, 50%) !important;
        }
      }

      .hide-in-desktop {
        display: none;
        max-height: 0px;
      }
    </style>
    <style>
      .email-container {
        max-width: 600px;
        min-width: 300px;
        margin: 0 auto;
        background-color: #242A75;
        font-family: Arial, Helvetica, sans-serif;
        color: #000;
      }

      .logo-cell {
        padding: 30px 0 0 30px;
        text-align: left;
      }

      .logo-cell img {
        max-width: 100px;
        height: auto;
      }

      .spacer-cell {
        height: 70px;
        line-height: 70px;
      }

      @media only screen and (max-width: 600px) {
        .hide-mobile {
          display: none !important;
          max-height: 0;
          overflow: hidden;
          mso-hide: all;
        }
      }
    </style>
    <!--[if mso]>
    <style type="text/css">
      .tolkien-column { width: 100% !important; }
      ul > li { text-indent: -1em; }
      a { border: none !important; }
    </style>
    <![endif]-->
  </head>
"""

    def _html_body_start(self):
        return """
  <body style="min-width:260px; min-height:100%; padding:0; margin:0 auto; background-color:#EDF1F4;">
    <center>
      <table border="0" cellpadding="0" cellspacing="0" align="center" role="presentation">
        <tr>
          <td width="600">
            <table class="color-wrap" width="100%" cellpadding="0" cellspacing="0" style="background:#EDF1F4;" role="presentation">
              <tbody>
                <tr>
                  <td>
        """

    def _logo_table(self):
        img = {
            'company_logo': mail_config['logos'].get('company', 'https://example.com/logo.png')
        }
        return f"""
                    <table class="email-container" role="presentation">
                      <tr>
                        <td>
                          <table role="presentation" width="100%">
                            <tr>
                              <td class="logo-cell">
                                <img src="{img['company_logo']}" alt="Company Logo">
                              </td>
                              <td class="spacer-cell hide-mobile">&nbsp;</td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                    </table>
        """

    def _type_mail_table(self):
        img = {
            'type_mail_logo': mail_config['logos'].get('acknowledge', 'https://example.com/type_mail_logo.png')
        }
        return f"""
                    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;min-width:300px;margin:0 auto;" role="presentation">
                      <tbody>
                        <tr>
                          <td>
                            <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
                              <tbody>
                                <tr>
                                  <td>
                                    <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
                                      <tbody>
                                        <tr>
                                          <td style="text-align:left;vertical-align:top;font-size:0px">
                                            <table cellpadding="0" cellspacing="0" style="display:inline-table;width:100%;min-width:480px;font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#000000;background:transparent;" role="presentation">
                                              <tbody>
                                                <tr>
                                                  <td style="text-align:center;line-height:0;padding:0;height:140px;">
                                                    <img src="{img['type_mail_logo']}" alt="" style="width:100%;max-width:600px;height:auto;display:block;" />
                                                  </td>
                                                </tr>
                                              </tbody>
                                            </table>
                                          </td>
                                        </tr>
                                      </tbody>
                                    </table>
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                          </td>
                        </tr>
                      </tbody>
                    </table>
        """

    def _body_table(self):
        msg = {
            'To': self.recipient,
            'group': mail_config.get('group', 'Your Group'),
            'online': mail_config.get('submissions', 'https://example.com/online-portal')
        }
        return f"""
                    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;min-width:300px;margin:0 auto;background:#ffffff;">
                      <tr>
                        <td style="padding:30px;font-family:Arial, Helvetica, sans-serif;font-size:12px;color:#000000;">
                          <div style="line-height: 27px;">
                            <span style="font-size: 18px; color: rgb(0, 187, 221);">Dear {msg['To']},</span>
                          </div>
                          <br>
                          <div style="line-height: 18px;">{msg['group']} team thanks you for your submission.</div>
                          <br>
                          <div style="text-align: center; line-height: 18px;">Your submission has been registered; you can now follow the status of the analysis</div>
                          <div style="text-align: center; line-height: 18px;">
                            on the portal,
                            <a href="{msg['online']}" target="_blank" style="color: rgb(0, 187, 221); text-decoration: none;">here.</a>
                          </div>
                          <div style="text-align: center; line-height: 18px;">
                            The result should reach you by e-mail within the hour with one of the following conclusions:
                            <strong style="color: rgb(255, 0, 0);">dangerous*</strong>,
                            <strong style="color: rgb(255, 154, 0);">most likely suspicious*</strong>,
                            <strong style="color: rgb(55, 166, 91);">most likely safe*</strong>,
                            <strong style="color: rgb(0, 164, 233);">inconclusive*</strong>.
                          </div>
                        </td>
                      </tr>
                    </table>
          """

    def _html_footer_start(self):
        url = {
            'glossary': mail_config.get('glossary', 'https://example.com/glossary'),
            'inquiry': mail_config.get('inquiry', 'https://example.com/inquiry')
        }
        msg = {
            'inquiry': mail_config.get('inquiry_text', 'our inquiry page'),
            'online': mail_config.get('submissions', 'https://example.com/online-portal')
        }
        return f"""
                    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;min-width:300px;margin:0 auto;background:#242A75;">
                      <tr>
                        <td style="padding:30px 10px 30px 30px;font-family:Arial, Helvetica, sans-serif;font-size:12px;">
                          <div style="text-align: center; font-style: italic; color: #ffffff;">
                            To see the definition of these conclusion terms, visit the cybersecurity glossary,
                            <a href="{url['glossary']}" target="_blank" style="color: #ffffff; text-decoration: underline;">available here</a>.
                            In case of questions, do not hesitate to contact
                            <a href="{url['inquiry']}" target="_blank" style="color: #ffffff; text-decoration: underline;">{msg['inquiry']}.</a>
                          </div>
                          <div style="text-align: center; font-style: italic; color: #ffffff;">
                            You can also access the portal
                            <a href="{msg['online']}" target="_blank" style="color: #ffffff; text-decoration: underline;">here</a>,
                            to have technical details about the analysis.
                          </div>
                          <div style="text-align: center; font-style: italic; color: #ffffff;">
                            Your contribution to the Group security is fundamental in order to reinforce the detection and response capabilities to new threats.
                          </div>
                          <br>
                          <div style="text-align: center; font-style: italic; color: #ffffff;">
                            With our kindest regards,
                          </div>
                        </td>
                      </tr>
                    </table>
        """

    def _html_team_table(self):
        msg = {
            'group': mail_config.get('group', 'Your Group')
        }
        return f"""
                    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;min-width:300px;margin:0 auto;background:#ffffff;">
                      <tr>
                        <td style="background-color:#242A75;line-height:18px;padding:10px;border-top:2px solid #FFFFFF;border-bottom:2px solid #FFFFFF;">
                          <div style="text-align: center;">
                            <strong style="font-size:15px;color:#ffffff;">{msg['group']} Team</strong>
                          </div>
                        </td>
                      </tr>
                    </table>
        """

    def _html_footer_global(self):
        msg = {
            'global': mail_config.get('global', 'Global Security Team')
        }
        url = {
            'global': mail_config.get('global_url', 'https://example.com/global-security')
        }
        return f"""
                    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;min-width:300px;margin:0 auto;background:#ffffff;">
                      <tr>
                        <td style="padding:35px 0;background-color:#242A75;text-align:center;">
                          <a href="{url['global']}" target="_blank" style="text-decoration:none;color:#ffffff;font-family:Arial,sans-serif;font-size:14px;">{msg['global']}</a>
                        </td>
                      </tr>
                    </table>
        """

    def _html_social_media(self):
        url = {
            'linkedin': mail_config['socials'].get('linkedin', 'https://www.linkedin.com/company/your-company'),
            'twitter': mail_config['socials'].get('twitter', 'https://twitter.com/your_company'),
            'facebook': mail_config['socials'].get('facebook', 'https://www.facebook.com/yourcompany'),
            'instagram': mail_config['socials'].get('instagram', 'https://www.instagram.com/yourcompany'),
            'youtube': mail_config['socials'].get('youtube', 'https://www.youtube.com/yourcompany')
        }
        img = {
            'linkedin': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEIAAABCCAYAAADjVADoAAABS2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDIgNzkuMTYwOTI0LCAyMDE3LzA3LzEzLTAxOjA2OjM5ICAgICAgICAiPgogPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIi8+CiA8L3JkZjpSREY+CjwveDp4bXBtZXRhPgo8P3hwYWNrZXQgZW5kPSJyIj8+nhxg7wAAA09JREFUeJzt3EuoHEUUxvHftEJEiVcwiigE34oomQtXBI0xiojgUlH3rlyYhUIkoCCIm5gs1IVuVQTFTdyKRBME8YU3vsDHIosEhGuUCC4kyS0XVa2TsacncWrSfdP9h15M1Zk+p7853VNV3acHIQQ1LOJh3IVrcUmdcQtZwc/Yh3ewPMlwMEGIRezG3fOIrkE+wpP4aryjqDDejs+cfSLAVvHYto93jGbEAC/hiTMWVrO8gm3lh9GM2KE7IhCP9Z/MKDNiEZ/jnIaCaooTWMJymRG7dU8E4jG/SMyIoYqraMcYFuI4oes8UmBL01G0gC2DEMIKNjQdScOsDEIIq+IYosusFnoRoKgaYneSczPv7xj24zCux23WSMblFOIAHhKnvSW3411cntHPXBiEKQsSp8hR3IhfKvqW8KnqmW5ryBXcG6pFgC/EhZFWk0uI76f0f5vJz9zIJcS0AVnrB2y5rhHfYIjVir4FHMRFGfzMjVwZcQt2+u9f5Tq8qeUikC8jSvbhdRzCDXgcN2Xc/9zILcSapdX/7WeSnCPLPeIQe5zz8cBY24f4tcJ2g39vIxzFa3gP3+EPrMfVuF9cfL1i5qhLQj4WQggqto0Vtpsn2G5O/XtCCBdPsCm3dSGEnbmCb+Op8RYexJEpdn+Jy/HP5nDaNiEO4jFxmf1UeQGfzOq4bUIcEn/p0yHg+Vkdt02I/8v7+H2WHbRViGvwqpjyH+M5XFBjfwJfzuIw9wpVDjaJI9SFkbY70nafeCpUcXgWp23MiF1OFqHkXvWPKvw2i9O2CbEe99T01/Wd7kX2JNomxFXqY9o4L8dtE+LCKf1zu2PfNiEaoxci0QuR6IVI9EIkeiESvRCJXohEL0SiFyKRcxq+FX9WtF9a0baE8yrab57i4zJxFlrFlVO+W0t/gyfRnxqJXohEL0SiFyLRC5EoTF4V7hKrhen3GLvAkQI/NB1FC/ixEB8Z7jr7+1KmyLAQy4T3Nh1Jg3yAA2W541B8VLhrlX7HcauRcsdlPNNcPI2xQyqcHy+Sf1l3qoEnlkRLHU+LKXO2clw8xm2jjXWvTdil/u7zWmQvnlLxHolJQpRswqO4E9eJL9JYE6VJ4tRhBT+JY6W38fUk478BGKWaSGldMyAAAAAASUVORK5CYII=',
            'twitter': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEIAAABCCAYAAADjVADoAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAOkSURBVHgB7ZzfddowFIev0z70kRGcDRjBnaBkgpAJwgZ4A9IJQiaATgAbhA3EY9/aTnB7by1SImRZkq+UBPydo3ACIshfdH7WH5sCLCDiiB5uqVRUxlRK+NjsqOyprIuiePJ6B0mYUPmF54uicmse95Uh4YEeVlRGcL6UVJZ0rPXxky8i9Av3cDnM6ZgXh18K/kFPTOnhES6TG8qN9UGEgo8fiLH8pnL9SfeGKVwuX6j85Iz4BgMVixjDwLjgEysMvB5HXDKDCM0gQvM5oO4EmnNuKBWVGmThSdSs5bWSCk8VwqYJ6M8GIqH3LlEOhc3s2PY5pX49mBARzAIi4IZTecb+KCqltAQmVAQzi5TBDe0zvVfYLmGEPSQwMSL4YMaWxiyMegtLnQrj4M8sHRJ697YYEYwyG9bSoJml4TMMwyr+6O+tUIBYEcwG7N1fHdVp6z0h4TlxSHhAIfqIYGzdf2zUUejXe2zcOyTUKEhfEYxP92/rPa7wnOeSwEiIYKTDM6sERkqEQkuqY1x4uiRMMRFSIhg+6JHR8NDwfHRIiD31eiEpgmkLz+MsUHgqbISOUavlb4gjLYKJCk+HBLNXJSGFCKayHFBneL6VBCaVCOuQmJ7bGPVu34MEJpUIxhae5uSoLTx7T6JCSblCxQf4qvvTjhIv7NzA/wUeFrXClvWFrGB6astnmuOBmJGnKDlEMJXlQOdGHdupd4KZyCUiOjzxVFgScolgFMaHp8iag4ucy/lLHZYv6N+/Qnd43kFz6U86MA+PHW0wsyB7eOYQsfL4f9iyoPYQJkZqESeDqg4ZZhZkC8+UIhS6N2I26BeepYew3qQSodBvI8YnC7hul7DepBChMGwjprbUq4w6ycNTWkTsRoxPFtSWOmLhKSmiayNmGfpey3uShaekiL4bMQrtWXDci3yH6sFIiZDaiHmz8JQQIb0H4bP/sfIQFkRfEak2YnwWgGtLnSlG0kdEyo2YtvCcY5MHh9JWJ5hYETk2YhS2nIq7wIjwjBGxcjRAeiPmGSLAiPAMFdE6icJ0y++x120FhWfI5YW8ePKdCv/XzddYDje4BHk4JP/Q4xbC+QHNvWmdDNdia4YrbzWDCM0gQsMi9jCwYxE7GNiziC0MrAs9QOLbHc/57l8Xe9pour7Su013cLnU/OPfWYPvhIXmZo9Lo7Z+ewBm2nl+J7jnMNisJSg8X3gidrK+WriEQHOX8Dl8kcYemmHClsqTuSvP/AVkJTON13gofgAAAABJRU5ErkJggg==',
            'facebook': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEIAAABCCAYAAADjVADoAAABS2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDIgNzkuMTYwOTI0LCAyMDE3LzA3LzEzLTAxOjA2OjM5ICAgICAgICAiPgogPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIi8+CiA8L3JkZjpSREY+CjwveDp4bXBtZXRhPgo8P3hwYWNrZXQgZW5kPSJyIj8+nhxg7wAAAndJREFUeJztnLuKFEEUhr8uB40EL7viCwhmjohi4gaGPoD6BiY6Bi5ewMBcMdBIn0AEUwORFTYQWRYcxcBLYuywqyKI4DBlUKdlpunLyG716bbPl1VPNfXXR1UxXTPVifeeEo4A54FTwCHgQFnlBvIF+ASsAo+At0UVkwIRR4E7wOkY6RRZAZaB19kPXE7lq8Aa/58ECH1aI/RxhuyIuAdcqimUNveBQVqYHhHX6Y4ECH1dTgvpiOgD68AOpVBajIHjwDAdEXfpngSAHnAbwojok7OKdoy+A85qp2gA5xywpJ2iASwl3vsRsKCdRJlR4r2fAIl2EmUmDpMA4HrKAX4CT4BnwDtgE/hRUPcpcDJWEE0Rj4GLwGjO+uOIWdREPAQuKLWdS97TZ2w+A5cV2i1FQ8QD4JdCu6VoiFhRaLMSDRHvFdqsJPEVm5bbzG9gZ0WdW4SFdFfm+m4iLu51i/gO7KmoswnsrSHLDBpTo4raJUAzRahgIgQTIcT+iv0KODNVnmdh3ldw/SVweMuJCogtYgx8/cd7iurv32KWUtoyNXpE3kVri4gFIm8gtUXEwdgNtEXEYuwGYi+WPWa/KXrgW8U9x3Kundi2RAU08Vmjzjx/acvUiI6JEEyEYCIEEyGYCMFECCZCMBGCiRBMhGAiBBMhmAjBRAgmQjARgokQ6v4zWYLSr91V1L1n2VgcSpulDWPigA3tFA1gwwEftFM0gI+OcDi066zaUaZA3wFD4IV2EkWeA2/suGPmuOMQuKmXR40bhL7bkei0kH3WGADXiHxIRJkxoY+D6YtdfG3CFWQ6TFMkIiX7Io1F2nMYzhOOSc31Io0//E2Kh1+bj7YAAAAASUVORK5CYII=',
            'youtube': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADgAAAA4CAYAAACohjseAAAACXBIWXMAABYlAAAWJQFJUiTwAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJcSURBVHgB7ZrhUcIwGIbfoj/86QhxAmUCywY6gXUCdQJwAt1AnEA3ACYQJ7A//ScbxPejKVfuwAauTdLIc/ce0AtHX/Il35cmQOQkdQ201ilfROeUok7hl4XRnJolSfKOfRBj1ESHzxc1ojb+8ckGY9LwDUWvdYmcumaPzqsX1wzSnOLLBEUodpWMJl/LDyuDkZgrGdDkVN70KheHiMOc8FKOyaVBXcyUGeJBUXfyZhmiNCihmSIuJJWcHZmx94z4OKG+JURTxEsqBs8RLxdi0Hfp1Saqh8iJ3uAxdmNq5JMLFBOj3dBimnixrNgvEQiS2qg3i/vWtgYVAkNKMeqj7sZtxuCYhWuOwOA9SaXyUNfOxuB+K2Y3zOsa2BhcIFBML/7JIQ92ndYNciK7gkdc9OCTyaMKHnAVoor6MjlXwSGux2BGTWhyBEf4mGQUNTRhe4OW8TmLKmrcdtiGkCYyFGGr0AK+DUolMqL6bdW7u64Hm2RK3bZdyPvoQSmQUxobuFiluDQo4XhPUxKOMzjCVYjKg+VHm+q/aVwY7PswVtJ6iPo0JxyWS13HxqBCoOgtBw+q2BjMEC61i2kbg6mLqn9XTO06rGtnOwal6r9HIOhiy93qwEQiyxXYh2F5wiiHH2TMyd6Esv3CrolefiBFh/gXaSLYJ9cNkIvBT8RLnphk+YM4yXqmGJ4iTmblJPOI+Fjua1ZPG8oZUa/7CA2SozhxuGZQxuIH4jhx2C8Pxq7yoBmLA/irUpoiq576XUv05imXmByje+Qoeu7VqjVDNjP7B6HzQw31lrXhLyroqN+JpZsPAAAAAElFTkSuQmCC',
            'instagram': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEIAAABCCAYAAADjVADoAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyZpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNi1jMTQyIDc5LjE2MDkyNCwgMjAxNy8wNy8xMy0wMTowNjozOSAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTggKFdpbmRvd3MpIiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOkMxQjM0M0I2ODI1QjExRUI4NEVGRjE5MTJBQUYwMUFDIiB4bXBNTTpEb2N1bWVudElEPSJ4bXAuZGlkOkMxQjM0M0I3ODI1QjExRUI4NEVGRjE5MTJBQUYwMUFDIj4gPHhtcE1NOkRlcml2ZWRGcm9tIHN0UmVmOmluc3RhbmNlSUQ9InhtcC5paWQ6QzFCMzQzQjQ4MjVCMTFFQjg0RUZGMTkxMkFBRjAxQUMiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6QzFCMzQzQjU4MjVCMTFFQjg0RUZGMTkxMkFBRjAxQUMiLz4gPC9yZGY6RGVzY3JpcHRpb24+IDwvcmRmOlJERj4gPC94OnhtcG1ldGE+IDw/eHBhY2tldCBlbmQ9InIiPz7Mls4kAAAFsElEQVR42uxcaWxUVRS+HWhr2WpSQYFQGtA0CqJCwPgHUv8YN6wkIhoTG4P6w92IG4moccFoQlxiFGIlKuKGtmqKUkPFHySuRCIuMRaoOyVEqkhLZcbvOOfB6fG9N2/eNp15c5IvfffNvXfmnnf2e18rMpmMcaF64HKgCTgFGA9Um+Kgv4CfgN3Ah8CrwE6nzhUOjCAGrAQWAyNMaVCamXEn0OOFEQuBl4CxpjSJJOUaYL28mVKdbgLeKmEmEI0B1gG3OEnEpcylCpMMooVfxupyhBFkE3Ywt5JEpCYzyGZYqvFwAplgqckjlkRMxd9uG3uRFCJvMo0WvyTBTLAcxpIUB0tJpyZSDYq+JiecET8TI/qLKGyOig4RIzJlzTBmZIRzD3DS8yPQCwyy387XvVUCxwFTGNXFwIjfgbVAB7AV+Cfk+SkBPAs4H2gBTghr4rBUgxb8IAcnB2OS5hrgdmA5S03BGfEnsAj4oFCuD2gDxhWSESQJ5wCb1X3S5YuAMwCKXI/lJ3iM6lcrgjmK8Parz/tZwv7gGsI24G0utkg6G3gvkGRkgtF9xEeBUcAzwGAmOqK51wBj1HevCDJpEInYy0/7b26PY/WYG5NKfMGSsF94GMqZxvuNs/3Sc4IJRI9GyIR+NsaLuahCNBtYpVLq1YVQjXlCLCdHrA5XKTVoFWrSIO6f6fcLUgGe0OeivSji4Ox9hzZ958Xi/qd+3bdfRnwPHBbt0/L0NG8AVwCN7FFIr0812a2D1zkKldTo0j5d1RZ64lSNTiWqmzyOexeYpsbagcS9XYzrBpqAOqAFOCA+61JjO/0syC8j3lRfvj1H/zSwzAMDJMijLeexbrRdjVvnZ0F+9VrrYa5E6G72KpKqgPnAydz+FviIk7X/hJU9hfU3H9WLTTXWqKew26Vvh82Tvh7Ya9O3F7iB+8j+bS7z71TzPx2n1xj02I8M6m3qHvn6J4E6m/6Ubj8BPG+O7q+QRNxMxZMIYqFwJ3GhjcDXon0tsNTDuCuB60R7l8nuwEVawY2S5I+nhOj+PMbeq2xPWzEwosbh/lZxvQCYkMecdZxLyGDJjsYOJ0ZUOdz/VVzP9DFvo8NcRWcjqkKcq7oYVMPJok8S19/4mPc7ce1Un0wPJ0Y4JTpzxPUWYE8ec+4DukR7lkupcNirRrPKWO/J02v0O8xVdO7zXJM9hGbRs0Crh3EvAE+Jdj2n+sOOEV6LpCNtcoylHCnucyj/0WctHFFatMrF8IZiI/wmXaNsCjVOdJ7JnmRbKULmxznUplL8icIwbrGZ68Yc0qBtxOg4GaEDqIEc/R/irPAxZWA7XMZQrnEX8EAca/KrGjqa+y1H/wpWkXagwcP8VB3fwOl3rsNtej91QpwScbxqey2PLWQD2sb4hJlYyTHHLPYOzXkEY3qzZ0qcjDjJZDdkrbrll3ka2ksYYdBnSsLr41QN2rqbLdrtJvydb6/VqA2iPdclAYwsjmhWqtFaAEa8yLUKiy70O1GQLT/KBqeL8Jq2/DarsDpK2sbut+BbfhOBO0S7j2sOqyNWE7JLVMqbb4bunt/qlwlBJcLSUbtjAVPZQ8xhK17LEiNfeRhh/n+moc8M3Tg6zPf6zNFjAe1KHQwXcDYGSfvDOCjSx/aiyxSGFjBzaguddNFT3QSs8GuxA0S3lM12BmVCWBKhI8y1wDvAx0rMwyBSp3nABZyYTQpr4ijPWR4AfgB+4cToYI7kzCleqeGQfiInaKOj+LHlA6fCRgyU2WAOpbgYknTqJUbsKPPBfJWyCYaSSF1kLBvYuif5VabpKQ5XX0uwNNDad5Vfd1SvO1JCc7UZWkIvdcrwmnt0rvGKyb4mnE4IE5bxmo9ElrpTEl6Sp5M7L+fKPuk1gJnMrVKSjjSvaYZmgpNESJL/SIMmoD2DyiJZOB1428NOoIu9Q7dT538FGACUwCRHK00nRwAAAABJRU5ErkJggg==',
        }
        return f"""
                    <table align="center" bgcolor="#242A75" cellpadding="0" cellspacing="0" style="margin: 15px auto 20px; text-align: center;">
                      <tr>
                        <td style="padding: 0 5px;">
                          <a data-targettype="webpage" href="{url['linkedin']}" style="border: O; text-decoration: none;" target="_blank">
                            <img alt="LinkedIn logo" height="20" src="{img['linkedin']}" style="border: 0px;" title="LinkedIn" width="20">
                          </a>
                        </td>
                        <td style="padding: 0 5px;">
                          <a href="{url['twitter']}" style="border: 0; text-decoration: none;" target="_blank" title="Twitter">
                            <img alt="Twitter logo" height="20" src="{img['twitter']}" style="border: 0px;" title="Twitter" width="20">
                          </a>
                        </td>
                        <td style="padding: 0 5px;">
                          <a href="{url['facebook']}" style="text-decoration: none;" target="_blank" title="">
                            <img alt="Facebook logo" height="20" src="{img['facebook']}" style="border: 0px;" title="Facebook" width="20">
                          </a>
                        </td>
                        <td style="padding: 0 5px;">
                          <a href="{url['youtube']}" style="text-decoration: none;" target="_blank" title="">
                            <img alt="YouTube logo" height="20" src="{img['youtube']}" style="border: 0px;" title="YouTube" width="20">
                          </a>
                        </td>
                        <td style="padding: 0 5px;">
                          <a href="{url['instagram']}" target="_blank" style="text-decoration: none;">
                            <img alt="Instagram logo" height="20" src="{img['instagram']}" style="border: 0px;" title="Instagram" width="20">
                          </a>
                        </td>
                      </tr>
                    </table>
        """

    def _html_footer_end(self):
        return """
                  </td>
                </tr>
              </tbody>
            </table>
          </td>
        </tr>
      </table>
  </body>
</html>
"""

    def _html_table(self):
        html = self._logo_table()
        html += self._type_mail_table()
        html += self._body_table()
        html += self._html_footer_start()
        html += self._html_team_table()
        html += self._html_footer_global()
        html += self._html_social_media()
        html += self._html_footer_end()
        return html

    def send(self):
        """
        Send the email using the SMTP server.
        """
        msg = MIMEMultipart()
        msg['From'] = self.sender
        if self.infos != "":
            msg['To'] = str(self.infos)
        else:
            msg['To'] = str(self.recipient)
        msg['Subject'] = str(self.subject)
        # Attach the HTML content to the email
        html_content = self._html_table()
        msg.attach(MIMEText(html_content, 'html'))

        # Connect to the SMTP server
        server = smtplib.SMTP(mail_config.get("server"), mail_config.get("port", 587))
        # Send the email
        text = msg.as_string()
        server.sendmail(self.sender, str(self.recipient), text)

        # Close the connection
        server.quit()

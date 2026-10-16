from django import forms
from django.conf import settings

# Must match api.serializers.submit.DEFAULT_CONTEXT_MAX_LENGTH: the serializer
# has already validated the text, the form must not truncate or reject it.
_CONTEXT_MAX_LENGTH = getattr(settings, "SUBMIT_CONTEXT_MAX_LENGTH", 2000)


class _ContextField(forms.CharField):
    """Optional reporter free text. Without a declared field Django drops the
    value from ``cleaned_data`` and the case never gets its reporter context."""

    def __init__(self, **kwargs):
        super().__init__(required=False, max_length=_CONTEXT_MAX_LENGTH, **kwargs)


class UploadFileForm(forms.Form):
    file = forms.FileField()
    context = _ContextField()

class UploadURLForm(forms.Form):
    url = forms.URLField(max_length=2048)
    context = _ContextField()

class UploadOtherForm(forms.Form):
    other = forms.CharField(max_length=255, required=True)
    context = _ContextField()

class AllowListForm(forms.Form):
    domain = forms.CharField(max_length=255, required=True)

class DeleteAllowListForm(forms.Form):
    deletedomain = forms.CharField(max_length=255, required=True)

class EmailForm(forms.Form):
    username = forms.EmailField(label="Email", max_length=50)
    password = forms.CharField(label="Password", max_length=255, widget=forms.PasswordInput)
    server = forms.CharField(label="Server", max_length=255)
    port = forms.IntegerField(label="Port")
from django import forms

class UploadFileForm(forms.Form):
    file = forms.FileField()

class UploadURLForm(forms.Form):
    # URL model stores `address` as a TextField, so 255 was an artificial cap
    # that rejected legitimate long URLs. 2048 matches the serializer bound and
    # the de-facto browser URL limit.
    url = forms.URLField(max_length=2048)

class UploadOtherForm(forms.Form):
    other = forms.CharField(max_length=255, required=True)

class AllowListForm(forms.Form):
    domain = forms.CharField(max_length=255, required=True)

class DeleteAllowListForm(forms.Form):
    deletedomain = forms.CharField(max_length=255, required=True)

class EmailForm(forms.Form):
    username = forms.EmailField(label="Email", max_length=50)
    password = forms.CharField(label="Password", max_length=255, widget=forms.PasswordInput)
    server = forms.CharField(label="Server", max_length=255)
    port = forms.IntegerField(label="Port")
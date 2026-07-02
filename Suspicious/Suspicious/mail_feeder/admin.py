from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from .models import (
    Mail, MailAnalyzed, MailArtifact, MailAttachment, MailBody, MailHeader, MailInfo,
    ArtifactIsDomain, ArtifactIsHash, ArtifactIsIp, ArtifactIsMailAddress, ArtifactIsUrl,MailArchive
)

# Resources for models
class MailResource(resources.ModelResource):
    class Meta:
        model = Mail
        fields = ('id', 'subject', 'reportedBy', 'date', 'to', 'cc', 'mail_id', 'times_sent', 'creation_date', 'last_update')
        export_order = ('id', 'subject', 'reportedBy', 'date', 'to', 'cc', 'mail_id', 'times_sent', 'creation_date', 'last_update')

class MailAnalyzedResource(resources.ModelResource):
    class Meta:
        model = MailAnalyzed
        fields = ('id', 'mail', 'is_phishing', 'is_dangerous', 'is_legitimate', 'is_spam', 'creation_date', 'last_update')

class MailArtifactResource(resources.ModelResource):
    class Meta:
        model = MailArtifact
        fields = ('id', 'artifact_score', 'artifact_confidence', 'artifact_level', 'artifact_type', 'creation_date', 'last_update')

class MailAttachmentResource(resources.ModelResource):
    class Meta:
        model = MailAttachment
        fields = ('id', 'attachment_score', 'attachment_confidence', 'attachment_level', 'att_hash_score', 'att_hash_confidence', 'file', 'creation_date', 'last_update')

class MailBodyResource(resources.ModelResource):
    class Meta:
        model = MailBody
        fields = ('id', 'body_score', 'body_confidence', 'body_level', 'body_value', 'fuzzy_hash', 'times_sent', 'creation_date', 'last_update')

class MailHeaderResource(resources.ModelResource):
    class Meta:
        model = MailHeader
        fields = ('id', 'header_score', 'header_confidence', 'header_level', 'header_value', 'fuzzy_hash', 'times_sent', 'creation_date', 'last_update')

class MailInfoResource(resources.ModelResource):
    class Meta:
        model = MailInfo
        fields = ('id', 'user', 'mail', 'is_received', 'user_reception_informed', 'is_analyzed', 'user_analysis_informed', 'is_phishing', 'user_phishing_informed', 'is_dangerous', 'user_dangerous_informed', 'creation_date', 'last_update')

class ArtifactIsDomainResource(resources.ModelResource):
    class Meta:
        model = ArtifactIsDomain
        fields = ('id', 'domain', 'artifact', 'associated_mails', 'times_sent', 'creation_date', 'last_update')

class ArtifactIsHashResource(resources.ModelResource):
    class Meta:
        model = ArtifactIsHash
        fields = ('id', 'hash', 'artifact', 'associated_mails', 'times_sent', 'creation_date', 'last_update')

class ArtifactIsIpResource(resources.ModelResource):
    class Meta:
        model = ArtifactIsIp
        fields = ('id', 'ip', 'artifact', 'associated_mails', 'times_sent', 'creation_date', 'last_update')

class ArtifactIsMailAddressResource(resources.ModelResource):
    class Meta:
        model = ArtifactIsMailAddress
        fields = ('id', 'mail_address', 'artifact', 'associated_mails', 'times_sent', 'creation_date', 'last_update')

class ArtifactIsUrlResource(resources.ModelResource):
    class Meta:
        model = ArtifactIsUrl
        fields = ('id', 'url', 'artifact', 'associated_mails', 'times_sent', 'creation_date', 'last_update')


# Admin classes
@admin.register(Mail)
class MailAdmin(ImportExportModelAdmin):
    resource_class = MailResource
    list_display = ('subject', 'reportedBy', 'date', 'to', 'cc', 'mail_id', 'times_sent', 'creation_date', 'last_update')
    list_filter = ('date', 'times_sent')
    list_select_related = ('mail_header', 'mail_body')
    search_fields = ('subject', 'mail_id', 'reportedBy', 'to', 'cc')
    ordering = ('-creation_date',)
    readonly_fields = ('preview_link',)

    @admin.display(description="Preview")
    def preview_link(self, obj):
        """Render a clickable link to the authed API preview endpoint.

        We deliberately do not embed an <img> here: the admin only
        serves authenticated staff, and routing all preview reads
        through /api/cases/<case_id>/mail-preview.png keeps a single
        access path that respects CanAccessSubmission. The link
        resolves the linked Case by walking back through CaseHasFileOrMail.
        """
        if not obj.preview_object_key:
            return "No preview"

        link = obj.case_has_file_or_mail.values_list("cases__id", flat=True).first()
        if not link:
            return "No case linked"

        from django.utils.html import format_html
        return format_html(
            '<a href="/api/cases/{}/mail-preview.png" target="_blank">View preview ({})</a>',
            link, obj.preview_object_key,
        )

# Admin classes
@admin.register(MailArchive)
class MailArchiveAdmin(ImportExportModelAdmin):
    resource_class = MailResource

@admin.register(MailAnalyzed)
class MailAnalyzedAdmin(ImportExportModelAdmin):
    resource_class = MailAnalyzedResource
    list_display = ('mail', 'is_phishing', 'is_dangerous', 'is_legitimate', 'is_spam', 'creation_date')
    list_filter = ('is_phishing', 'is_dangerous', 'is_legitimate', 'is_spam', 'creation_date')
    list_select_related = ('mail',)
    search_fields = ('mail__subject',)
    ordering = ('-creation_date',)

@admin.register(MailArtifact)
class MailArtifactAdmin(ImportExportModelAdmin):
    resource_class = MailArtifactResource
    list_display = ('artifact_type', 'artifact_score', 'artifact_confidence', 'artifact_level', 'creation_date')
    list_filter = ('artifact_type', 'artifact_level', 'creation_date')
    list_select_related = ('mail',)
    search_fields = ('artifact_type',)
    ordering = ('-creation_date',)

@admin.register(MailAttachment)
class MailAttachmentAdmin(ImportExportModelAdmin):
    resource_class = MailAttachmentResource
    list_display = ('file', 'attachment_score', 'attachment_confidence', 'att_hash_score', 'att_hash_confidence', 'creation_date')
    list_filter = ('attachment_level', 'creation_date')
    list_select_related = ('file', 'mail')
    search_fields = ('file__file_path',)
    ordering = ('-creation_date',)

@admin.register(MailBody)
class MailBodyAdmin(ImportExportModelAdmin):
    resource_class = MailBodyResource
    list_display = ('fuzzy_hash', 'body_score', 'body_confidence', 'body_level', 'times_sent', 'creation_date')
    list_filter = ('body_level', 'times_sent', 'creation_date')
    search_fields = ('fuzzy_hash',)
    ordering = ('-creation_date',)

@admin.register(MailHeader)
class MailHeaderAdmin(ImportExportModelAdmin):
    resource_class = MailHeaderResource
    list_display = ('fuzzy_hash', 'header_score', 'header_confidence', 'header_level', 'times_sent', 'creation_date')
    list_filter = ('header_level', 'times_sent', 'creation_date')
    search_fields = ('fuzzy_hash',)
    ordering = ('-creation_date',)

@admin.register(MailInfo)
class MailInfoAdmin(ImportExportModelAdmin):
    resource_class = MailInfoResource
    list_display = ('user', 'mail', 'is_received', 'is_analyzed', 'is_phishing', 'is_dangerous', 'creation_date')
    list_filter = ('is_received', 'is_analyzed', 'is_phishing', 'is_dangerous', 'creation_date')
    list_select_related = ('user', 'mail')
    search_fields = ('mail__subject', 'user__username')
    ordering = ('-creation_date',)

@admin.register(ArtifactIsDomain)
class ArtifactIsDomainAdmin(ImportExportModelAdmin):
    resource_class = ArtifactIsDomainResource
    list_display = ('domain', 'artifact', 'times_sent', 'creation_date')
    list_filter = ('creation_date',)
    list_select_related = ('domain', 'artifact')
    search_fields = ('domain__value',)
    ordering = ('-creation_date',)

@admin.register(ArtifactIsHash)
class ArtifactIsHashAdmin(ImportExportModelAdmin):
    resource_class = ArtifactIsHashResource
    list_display = ('hash', 'artifact', 'times_sent', 'creation_date')
    list_filter = ('creation_date',)
    list_select_related = ('hash', 'artifact')
    search_fields = ('hash__value',)
    ordering = ('-creation_date',)

@admin.register(ArtifactIsIp)
class ArtifactIsIpAdmin(ImportExportModelAdmin):
    resource_class = ArtifactIsIpResource
    list_display = ('ip', 'artifact', 'times_sent', 'creation_date')
    list_filter = ('creation_date',)
    list_select_related = ('ip', 'artifact')
    search_fields = ('ip__address',)
    ordering = ('-creation_date',)

@admin.register(ArtifactIsMailAddress)
class ArtifactIsMailAddressAdmin(ImportExportModelAdmin):
    resource_class = ArtifactIsMailAddressResource
    list_display = ('mail_address', 'artifact', 'times_sent', 'creation_date')
    list_filter = ('creation_date',)
    list_select_related = ('mail_address', 'artifact')
    search_fields = ('mail_address__address',)
    ordering = ('-creation_date',)

@admin.register(ArtifactIsUrl)
class ArtifactIsUrlAdmin(ImportExportModelAdmin):
    resource_class = ArtifactIsUrlResource
    list_display = ('url', 'artifact', 'times_sent', 'creation_date')
    list_filter = ('creation_date',)
    list_select_related = ('url', 'artifact')
    search_fields = ('url__address',)
    ordering = ('-creation_date',)

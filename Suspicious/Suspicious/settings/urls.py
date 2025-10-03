from django.urls import path
from django.views.generic import RedirectView

from settings import views


app_name = 'settings'

urlpatterns = [
    path('logout/', views.logout_view, name='logout'),

    # User settings
    path('settings/', views.settings, name='settings'),
    
    # Path to get the email feeder status
    path('get-email-feeder-status/', views.get_email_feeder_status, name='get_email_feeder_status'),

    # Path to toggle the email feeder
    path('toggle-email-feeder/', views.toggle_email_feeder, name='toggle_email_feeder'),

    # Update analyzer weight
    path('update-analyzer-weight/<analyzer_id>/<weight>/', views.update_analyzer_weight, name='update_analyzer_weight'),
    
    # File AllowList
    
    ## Add file by name
    path('add-file/<str:file>/', views.add_file_by_name, name='add_file_by_name'),
    
    ## Add file by upload
    path('add-file-by-upload/', views.add_file_by_upload, name='add_file_by_upload'),
    
    ## Remove file by name
    path('remove-file/<str:file>/', views.remove_file_by_name, name='remove_file_by_name'),

    # Filetype AllowList
    
    ## Add filetype by name
    path('add-filetype/<str:filetype>/', views.add_filetype_by_name, name='add_filetype_by_name'),

    ## Add filetype by upload

    path('add-filetype-file/', views.add_filetype_by_upload, name='add_filetype_by_upload'),

    ## Remove filetype by name
    path('remove-filetype/<str:filetype>/', views.remove_filetype_by_name, name='remove_filetype_by_name'),
    
    ## Domain AllowList
    
    ## Add domain by name
    path('add-domain/<str:domain>/', views.add_domain_by_name, name='add_domain_by_name'),
    
    ## Add domain by upload
    path('add-domain-file/', views.add_domain_by_upload, name='add_domain_by_upload'),
    
    ## Remove domain by name
    path('remove-domain/<str:domain>/', views.remove_domain_by_name, name='remove_domain_by_name'),
    
    ## Domain DenyList
    
    ## Add domain by name
    path('add-Bdomain/<str:domain>/', views.add_bdomain_by_name, name='add_bdomain_by_name'),
    
    ## Add domain by upload
    path('add-Bdomain-file/', views.add_bdomain_by_upload, name='add_bdomain_by_upload'),
    
    ## Remove domain by name
    path('remove-Bdomain/<str:domain>/', views.remove_bdomain_by_name, name='remove_bdomain_by_name'),

    ## Campaign Domain AllowList
    
    ## Add campaign domain by name
    path('add-campaign-domain/<str:domain>/', views.add_campaign_domain_by_name, name='add_campaign_domain_by_name'),
    
    ## Add campaign domain by upload
    path('add-campaign-domain-file/', views.add_campaign_domain_by_upload, name='add_campaign_domain_by_upload'),
    
    ## Remove campaign domain by name
    path('remove-campaign-domain/<str:domain>/', views.remove_campaign_domain_by_name, name='remove_campaign_domain_by_name'),

    # CISO Profile

    ## add ciso
    path('add-ciso/<str:ciso>/', views.add_ciso_by_name, name='add_ciso_by_name'),
    
    ## add ciso by upload
    path('add-ciso-file/', views.add_ciso_by_upload, name='add_ciso_by_upload'),
    
    ## remove ciso
    path('remove-ciso/<str:ciso>/', views.remove_ciso_by_name, name='remove_ciso_by_name'),
    
    # Change email address
    path('change-email/<changed_values>/', views.change_email, name='change_email'),
    
    # Redirect to home page
    path('', RedirectView.as_view(url='/')),
]
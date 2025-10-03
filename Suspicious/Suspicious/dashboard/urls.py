from django.urls import include, path
from django.views.generic import RedirectView

from . import views


app_name = 'dashboard'

urlpatterns = [
    path('logout/', views.logout_view, name='logout'),

    # Dashboard for a specific month and year
    path('dashboard-change/<month>/<year>/', views.dashboard_change, name='dashboard'),
    
    # Dashboard for a specific month, year, and scope
    path('dashboard-change-scope/<month>/<year>/<scope>/', views.dashboard_change_scope, name='dashboard_change_scope'),

    # Dashboard
    path('dashboard/', views.dashboard, name='dashboard'),

    # New Campaigns page
    path('dashboard/campaigns/', views.dashboard_campaigns, name='dashboard_campaigns'),

    # Classification counts for campaigns page
    path('dashboard/campaigns/classification-counts/', views.dashboard_campaigns_classification_counts, name='dashboard_campaigns_classification_counts'),

    # PCA data for campaigns page
    path('dashboard/campaigns/pca/', views.dashboard_campaigns_pca, name='dashboard_campaigns_pca'),

    # Mail volume (last 14 days) for campaigns page
    path('dashboard/campaigns/mail-volume/', views.dashboard_campaigns_mail_volume, name='dashboard_campaigns_mail_volume'),

    # Include URL patterns from other apps
    path('accounts/', include('django.contrib.auth.urls')),

    # Redirect to home page
    path('', RedirectView.as_view(url='/')),
]

from django.urls import path
from django.views.generic import RedirectView

from profiles import views


app_name = 'profiles'

urlpatterns = [
    path('logout/', views.logout_view, name='logout'),

    # User settings
    path('profile/', views.profile, name='profile'),
    
    path('update-preferences/', views.update_preferences, name='update_preferences'),
    
    path('update-appearance/', views.update_appearance, name='update_appearance'),
    
    # Redirect to home page
    path('', RedirectView.as_view(url='/')),
]
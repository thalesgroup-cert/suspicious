from django.urls import include, path
from django.views.generic import RedirectView

from tasp import views


app_name = 'tasp'
urlpatterns = [
    # Home page
    path('', views.home,name='home'),

    # logout
    path('logout/', views.logout_view, name='logout'),
    
    # Submission form
    path('submit/', views.submit, name='submit'),
    
    # List of submissions
    path('submissions/', views.submissions, name='submissions'),

    # Update CISO profile scope
    path('update-ciso-profile-scope/<str:scope>/', views.update_ciso_profile_scope, name='update_ciso_profile_scope'),
    
    # Add row to tasp
    #path('add-row-tasp/<case_id>/<id>/<ope>/<custom>', views.add_row_tasp, name='add_row_tasp'),

    path('set-ioc-level/<id>/<type>/<level>/<case_id>', views.set_ioc_level, name='set_ioc_level'),

    # crezte case popup
    path('create-case-popup/<case_id>/<user>', views.create_case_popup, name='create_case_popup'),

    path('edit-global/<case_id>/<score>/<confidence>/<classification>', views.edit_global, name='edit'),

    path('get-link-analyzer/<value>/<ioc_type>', views.get_link_analyzer, name='get_link_analyzer'),

    path('challenge/<case_id>', views.challenge, name='challenge'),

    # About page
    path('about/', views.about, name='about'),
    
    # Compute page
    path('compute/<id>/<user>', views.compute, name='compute'),

    # Investigation page
    path('tasp-admin/', views.tasp, name='tasp'),

    # Include URL patterns from other apps
    path('accounts/', include('django.contrib.auth.urls')),

    # Redirect to home page
    path('', RedirectView.as_view(url='/')),
]
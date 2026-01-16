from django.urls import path
from . import views

urlpatterns = [
    path('kpis/', views.KpiListView.as_view(), name='kpi-list'),
    path('kpis/<int:pk>/', views.KpiDetailView.as_view(), name='kpi-detail'),
    path('monthly-cases/', views.MonthlyCasesSummaryListView.as_view(), name='monthly-cases-list'),
    path('monthly-cases/aggregate/', views.MonthlyCasesSummaryAggregateView.as_view(), name='monthly-cases-aggregate'),
    path('monthly-reporters/', views.MonthlyReporterStatsListView.as_view(), name='monthly-reporters-list'),
    path('total-cases/', views.TotalCasesStatsListView.as_view(), name='total-cases-list'),
    path('user-cases/', views.UserCasesMonthlyStatsListView.as_view(), name='user-cases-list'),
    path('user-cases/aggregate/', views.UserCasesMonthlyStatsAggregateView.as_view(), name='user-cases-aggregate'),
]

"""recipe_management URL Configuration
"""
from django.urls import include, path
from django.contrib import admin

urlpatterns = [
    path('v1/', include('recipes.urls')),
    path('admin/', admin.site.urls),
    path('', include('django_prometheus.urls'))
]

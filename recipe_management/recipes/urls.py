from django.urls import path
from . import views

urlpatterns = [
    path('user', views.user),
    path('user/self', views.update_user),
    path('recipe/', views.create_recipe),
    path('recipes', views.get_newest_recipe),
    path('recipe/<id>', views.recipe_crud),
    path('get/random/recipe', views.get_random_recipe),
    path('health', views.health_check),
    path('recipe/<id>/image', views.upload_image)
]

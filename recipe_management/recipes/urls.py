from django.urls import path
from . import views

urlpatterns = [
    path('user', views.user),
    path('user/self', views.update_user),
    path('recipe/', views.create_recipe),
    path('recipes', views.get_newest_recipe),
    path('recipe/<id>', views.recipe_crud)

]

from rest_framework import serializers
from .models import User, Recipes, OrderedList, NutritionalInformation, Image


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email_address', 'account_created', 'account_updated']


class GetUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email_address', 'account_created', 'account_updated']


class OrderlistSerializer(serializers.ModelSerializer):

    class Meta:
        model = OrderedList
        fields = ['position', 'items']


class NutritionaInfoSerializer(serializers.ModelSerializer):

    class Meta:
        model = NutritionalInformation
        fields = ['calories', 'cholesterol_in_mg', 'sodium_in_mg', 'carbohydrates_in_grams', 'protein_in_grams']


class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = ['id', 'urls']


class RecipeSerializer(serializers.ModelSerializer):

    steps = OrderlistSerializer(many=True)
    images = ImageSerializer(many=True)
    nutrition_information = NutritionaInfoSerializer()
    images = ImageSerializer(many=True)

    class Meta:
        model = Recipes
        fields = ['id', 'created_ts', 'updated_ts', 'author_id', 'cook_time_in_min', 'prep_time_in_min',
                  'total_time_in_min', 'title', 'cuisine', 'servings', 'ingredients', 'steps',
                  'nutrition_information', 'images']

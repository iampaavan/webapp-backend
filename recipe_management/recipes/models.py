from django.db import models
from django.contrib.postgres.fields import ArrayField
import uuid


class User(models.Model):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=256)
    last_name = models.CharField(max_length=256)
    password = models.CharField(max_length=256)
    email_address = models.EmailField(unique=True)
    account_created = models.DateTimeField(auto_now_add=True)
    account_updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'User'


class Recipes(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_ts = models.DateTimeField(auto_now_add=True, editable=False)
    updated_ts = models.DateTimeField(auto_now=True, editable=False)
    author_id = models.UUIDField(default=uuid.uuid4, editable=False)
    cook_time_in_min = models.IntegerField()
    prep_time_in_min = models.IntegerField()
    total_time_in_min = models.IntegerField()
    title = models.CharField(max_length=256)
    cuisine = models.CharField(max_length=256)
    servings = models.IntegerField()
    ingredients = ArrayField(models.CharField(max_length=200), blank=True)
    steps = ''
    nutrition_information = ''

    class Meta:
        db_table = 'Recipes'


class OrderedList(models.Model):
    position = models.IntegerField()
    items = models.CharField(max_length=256)

    class Meta:
        db_table = 'OrderedList'


class NutritionalInformation(models.Model):
    calories = models.IntegerField()
    cholesterol_in_mg = models.DecimalField(max_digits=5, decimal_places=2)
    sodium_in_mg = models.IntegerField()
    carbohydrates_in_grams = models.DecimalField(max_digits=5, decimal_places=2)
    protein_in_grams = models.DecimalField(max_digits=5, decimal_places=2)

    class Meta:
        db_table = 'NutritionalInformation'

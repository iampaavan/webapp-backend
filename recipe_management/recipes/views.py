import json
import boto3
import random
import bcrypt
import base64
import os
import logging
import redis
import uuid
from django.db import IntegrityError
from .serializers import UserSerializer, RecipeSerializer, GetUserSerializer, ImageSerializer
from django.core.exceptions import ValidationError
from django.core.validators import validate_email, RegexValidator
from django.http import HttpResponse, JsonResponse
from .validators import multipleValidator, minMaxvalidators, minValidator, uniqueValidator
from .models import User, Recipes, OrderedList, NutritionalInformation, Image
from boto.s3.connection import S3Connection, Bucket, Key
from django.conf import settings
from django.core.cache.backends.base import DEFAULT_TIMEOUT
from django.core.cache import cache
from django.views.decorators.cache import never_cache
from . import metrics

email = ""
logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=logging.DEBUG)
# BUCKET = os.environ.get("BUCKET_NAME")
# AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
# AWS_SECRET_KEY = os.environ.get("SECRET_ACCESS_KEY_ID")

BUCKET = 'dev-hgadhiya-csye7374-image-upload'
AWS_ACCESS_KEY = 'AKIAUJWRCG77QYGIF35U'
AWS_SECRET_KEY = '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'

CACHE_TTL = getattr(settings, 'CACHE_TTL', DEFAULT_TIMEOUT)
# conn = False

# Connect to our Redis instance
# try:
#     REDIS_CONN_POOL_1 = settings.REDIS_CONN_POOL_1
#     conn = redis.Redis(connection_pool=REDIS_CONN_POOL_1)
#     logging.debug(conn)
#
# except Exception as connection_exception:
#     logging.debug(connection_exception)


def user(request):
    if request.method == 'POST':
        logging.debug("Request Method: {}".format(request.method))
        logging.debug("Request Path: {}".format(request.path))
        metrics.user_created.inc()
        request_body = json.loads(request.body)
        logging.debug("request body: {}".format(request_body))
        required_params = ['first_name', 'last_name', 'password', 'email_address']
        if not request_body:
            logging.debug("Request Body Empty. Body should have {}".format(", ".join(required_params)))
            return JsonResponse("No body Provided", status=204, safe=False)
        missing_keys = check_params(required_params, request_body)
        if missing_keys:
            logging.debug("missing {} in request body".format(", ".join(missing_keys)))
            return HttpResponse("Missing {}".format(", ".join(missing_keys)), status=400,
                                content_type="application/json")

        first_name = request_body['first_name']
        last_name = request_body['last_name']
        email = request_body['email_address']
        pwd = request_body['password']
        try:
            validate_email(email)
        except ValidationError:
            logging.debug("Invalid email address {}".format(email))
            return HttpResponse("Invalid Email", status=400, content_type="application/json")
        try:
            validate = RegexValidator(regex='^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$')
            validate(pwd)
        except ValidationError:
            logging.debug("weak password")
            return HttpResponse("Enter a Strong Password", status=400, content_type="application/json")

        encrypt_pwd = encryptpwd(pwd)
        new_user = User(first_name=first_name, last_name=last_name, password=encrypt_pwd, email_address=email)
        ser = UserSerializer(new_user)
        try:
            new_user.save()
        except IntegrityError as e:
            logging.debug("User already exist")
            return HttpResponse("User already exists", status=400, content_type="application/json")
        logging.info("successfully created user with email: {}".format(email))
        return JsonResponse(ser.data, status=201)
    else:
        logging.debug("Invalid request method {} {}".format(request.method,request.path))
        return HttpResponse("Invalid Request method", status=400, content_type="application/json")


def update_user(request):
    if request.method == 'PUT':
        logging.debug("Request Method: {}".format(request.method))
        logging.debug("Request Path: {}".format(request.path))
        metrics.user_updated.inc()
        auth = request.headers.get('Authorization')
        if auth:
            auth_status = checkauth(auth)
        else:
            logging.debug("login credentials not provided")
            return JsonResponse("please provide login credentials", status=403, safe=False)
        request_body = json.loads(request.body)
        logging.debug("request body: {}".format(request_body))
        required_params = ['first_name', 'last_name', 'password', 'email_address']
        if not request_body:
            logging.debug("Request Body Empty. Body should have {}".format(", ".join(required_params)))
            return JsonResponse("No body Provided", status=204, safe=False)
        if auth_status == 'success':
            missing_keys = check_params(required_params, request_body)
            if missing_keys:
                logging.debug("missing {} in request body".format(", ".join(missing_keys)))
                return HttpResponse("Missing {}".format(", ".join(missing_keys)), status=400,
                                    content_type="application/json")

            user_obj = User.objects.get(email_address=email)
            changed = False
            for item in request_body.keys():
                if item == 'first_name' and user_obj.first_name != request_body['first_name']:
                    user_obj.first_name = request_body[item]
                    changed = True
                    continue
                elif item == 'last_name' and user_obj.last_name != request_body['last_name']:
                    user_obj.last_name = request_body['last_name']
                    changed = True
                    continue
                elif item == 'password' and not (
                        decryptpwd(request_body['password'].encode('utf-8'), user_obj.password)):
                    encrypted_pwd = encryptpwd(request_body['password'])
                    user_obj.password = encrypted_pwd
                    changed = True
                    continue
                elif request_body['email_address'] != user_obj.email_address:
                    logging.debug("cannot update email address")
                    return HttpResponse("Email address cannot be updated", status=400, content_type='application/json')
            if changed:
                ser = UserSerializer(user_obj)
                user_obj.save()
                logging.debug("success updated user with email: {}".format(email))
                return JsonResponse(ser.data, status=200)
            else:
                logging.debug("No changes found to update")
                return JsonResponse("No changes to update", status=200, safe=False)
        elif auth_status == "wrong_pwd":
            return JsonResponse("Wrong Password", status=403, safe=False)
        elif auth_status == "no_user":
            return JsonResponse("User Not Found", status=404, safe=False)

    elif request.method == 'GET':
        return get_user(request)

    else:
        logging.debug("Invalid request method {} {}".format(request.method, request.path))
        return JsonResponse("Invalid request method", status=400, safe=False)


def get_user(request):
    logging.debug("Request Method: {}".format(request.method))
    logging.debug("Request Path: {}".format(request.path))
    metrics.get_user.inc()
    auth = request.headers.get('Authorization')
    if auth:
        auth_status = checkauth(auth)
    else:
        logging.debug("login credentials not provided")
        return JsonResponse("please provide login credentials", status=403, safe=False)

    if auth_status == 'success':
        user_obj = User.objects.get(email_address=email)
        serialize = GetUserSerializer(user_obj)
        logging.debug("success got user details: {}".format(serialize.data))
        return JsonResponse(serialize.data, status=200)

    elif auth_status == 'wrong_pwd':
        return JsonResponse("Wrong Password", status=403, safe=False)

    elif auth_status == 'no_user':
        return JsonResponse("User Not Found", status=404, safe=False)


def create_recipe(request):
    if request.method == "POST":
        logging.info("Request Method: {}".format(request.method))
        logging.info("Request Path: {}".format(request.path))
        metrics.recipe_created.inc()
        auth = request.headers.get('Authorization')
        if auth:
            auth_status = checkauth(auth)
        else:
            logging.debug("login credentials not provided")
            return JsonResponse("please provide login credentials", status=403, safe=False)
        request_body = json.loads(request.body)
        logging.info("Body: {}".format(request_body))
        if auth_status == 'success':
            required_params = ['cook_time_in_min', 'prep_time_in_min', 'title', 'cuisine', 'servings', 'ingredients',
                               'steps', 'nutrition_information']
            missing_keys = check_params(required_params, request_body)
            if missing_keys:
                logging.debug("missing {} in request body".format(", ".join(missing_keys)))
                return JsonResponse("missing {}".format(", ".join(missing_keys)), status=400, safe=False)
            try:
                cook_time_in_min = multipleValidator(request_body['cook_time_in_min'], 'cook_time_in_min')
                prep_time_in_min = multipleValidator(request_body['prep_time_in_min'], 'prep_time_in_min')
                title = request_body['title']
                cuisine = request_body['cuisine']
                servings = minMaxvalidators(request_body['servings'], 1, 5, 'servings')
                ingredients = uniqueValidator(request_body['ingredients'], 'ingredients')
                steps = request_body['steps']
                steps_sort = sorted(steps, key=lambda k: k['position'], reverse=True)
                nutri_info = request_body['nutrition_information']
                total_time = multipleValidator(cook_time_in_min + prep_time_in_min, 'total_time')
                for item in steps:
                    minValidator(item['position'], 1, 'position')
            except ValidationError as e:
                logging.debug(e)
                return HttpResponse(e, status=400, content_type='application/json')

            author = User.objects.get(email_address=email)

            nutrition_obj = NutritionalInformation(calories=nutri_info['calories'],
                                                   cholesterol_in_mg=nutri_info['cholesterol_in_mg'],
                                                   sodium_in_mg=nutri_info['sodium_in_mg'],
                                                   carbohydrates_in_grams=nutri_info['carbohydrates_in_grams'],
                                                   protein_in_grams=nutri_info['protein_in_grams'])
            nutrition_obj.save()
            logging.info("success saved nutrition information to DB")

            recipe_obj = Recipes(author_id=author, cook_time_in_min=cook_time_in_min, prep_time_in_min=prep_time_in_min,
                                 total_time_in_min=total_time, title=title, cuisine=cuisine, servings=servings,
                                 ingredients=ingredients, nutrition_information=nutrition_obj)
            recipe_obj.save()

            for item in steps_sort:
                order_obj = OrderedList(position=item['position'], items=item['items'], recipe=recipe_obj)
                order_obj.save()
                logging.info("success saved order list to DB")

            ser = RecipeSerializer(recipe_obj)
            cache.set(str(recipe_obj.id), recipe_obj, timeout=CACHE_TTL)
            logging.info("success set recipe in cache")
            logging.info("success Recipe created")
            return JsonResponse(ser.data, status=201)

        elif auth_status == "wrong_pwd":
            return JsonResponse("Wrong Password", status=403, safe=False)

        elif auth_status == "no_user":
            return JsonResponse("User Not Found", status=404, safe=False)

    else:
        logging.debug("Invalid request method {} {}".format(request.method, request.path))
        return JsonResponse("Invalid request method", status=400, safe=False)


def upload_image(request, id):
    region = 'us-east-1'
    if request.method == "POST":
        logging.debug("Request Method: {}".format(request.method))
        logging.debug("Request Path: {}".format(request.path))
        metrics.image_uploaded.inc()
        auth = request.headers.get('Authorization')
        file = request.FILES['file']
        auth_status = checkauth(auth)
        try:
            if auth_status == "success":
                user = User.objects.get(email_address=email)
                cache_string = str(id)
                if cache_string in cache:
                    recipe_obj = cache.get(cache_string)
                    logging.debug("Cache hit success!! recipe found in cache")
                else:
                    recipe_obj = Recipes.objects.get(pk=id)
                    logging.debug("Cache miss!! recipe not found in cache")
                if not (recipe_obj.author_id == user):
                    logging.debug("Not authorized to update recipe")
                    return JsonResponse("You are not authorized to update this recipe", status=401, safe=False)
                else:
                    file_name = file.name
                    file_name = file_name + str(uuid.uuid4())
                    logging.debug("File Name: {}".format(file_name))
                    s3_bucket = BUCKET
                    s3_client = boto3.client(
                        's3',
                        aws_access_key_id=AWS_ACCESS_KEY,
                        aws_secret_access_key=AWS_SECRET_KEY)
                    s3_client.upload_fileobj(file, s3_bucket, file_name)
                    logging.debug("success image uploaded to bucket {}".format(s3_bucket))
                    s3_url = f"https://s3-{region}.amazonaws.com/{s3_bucket}/{file_name}"
                    logging.debug("S3 URL: {}".format(s3_url))

                    img_object = Image(urls=s3_url, recipe=recipe_obj)
                    img_object.save()
                    logging.debug("success image attached to recipe id: {}".format(recipe_obj.id))
                    ser = ImageSerializer(img_object)
                    cache.set(str(recipe_obj.id), recipe_obj, timeout=CACHE_TTL)
                    logging.debug("success save recipe in cache")
                    cache.set(str(img_object.id), img_object, timeout=CACHE_TTL)
                    logging.debug("success save image in cache")
                return JsonResponse(ser.data, status=200)

            elif auth_status == "wrong_pwd":
                return JsonResponse("Wrong Password", status=403, safe=False)

            elif auth_status == "no_user":
                return JsonResponse("User Not Found", status=404, safe=False)

        except Recipes.DoesNotExist:
            logging.debug("Recipe id {} Not Found".format(id))
            return JsonResponse("No recipe Found", status=404, safe=False)

        except ValidationError:
            logging.debug("Recipe id {} Not Found".format(id))
            return JsonResponse("Recipe not Found", status=404, safe=False)
        except Exception as e:
            logging.debug("S3 permission denied")
            return JsonResponse("Permission denied", status=403, safe=False)
    else:
        logging.debug("Invalid request method {} {}".format(request.method, request.path))
        return JsonResponse("Invalid request method", status=400, safe=False)

@never_cache
def get_newest_recipe(request):
    if request.method == 'GET':
        logging.info("Request Method: {}".format(request.method))
        logging.info("Request Path: {}".format(request.path))
        metrics.newest_recipe.inc()
        try:
            recipe_obj = Recipes.objects.latest('updated_ts')
            serialize = RecipeSerializer(recipe_obj)
            return JsonResponse(serialize.data, status=200, safe=False, json_dumps_params={'indent': 4})

        except Recipes.DoesNotExist:
            logging.debug("Recipe not found")
            return JsonResponse("Recipe not Found", status=404, safe=False)
        except ValidationError:
            logging.debug("Recipe not found")
            return JsonResponse("Recipe not Found", status=404, safe=False)
    else:
        logging.debug("Invalid request method {} {}".format(request.method, request.path))
        return JsonResponse("Bad Request", status=400, safe=False)


def redis_health_check(request):
    if request.method == 'GET':
        metrics.redis_health.inc()
        try:
            host = os.environ.get("redisHost")
            port = os.environ.get("redisPort")
            password = os.environ.get("redisPass")
            conn = redis.StrictRedis(host=host, port=port, password=password)
            if conn.ping():
                logging.debug("success redis ping")
                return HttpResponse("Redis Connected", status=200, content_type='application/json')
            else:
                return HttpResponse("Redis Connection failed", status=400, content_type='application/json')
        except Exception as e:
            return HttpResponse(e, status=400, content_type='application/json')


@never_cache
def get_random_recipe(request):
    metrics.random_recipe.inc()
    if request.method == 'GET':
        logging.debug("Request Method: {}".format(request.method))
        logging.debug("Request Path: {}".format(request.path))
        try:
            recipe_obj = Recipes.objects.all()
            random_item = random.choice(recipe_obj)
            serialize = RecipeSerializer(random_item)
            logging.debug("success get random recipe")
            return JsonResponse(serialize.data, status=200, safe=False, json_dumps_params={'indent': 4})

        except Recipes.DoesNotExist:
            logging.debug("No recipes Found")
            return JsonResponse("Recipe not Found", status=404, safe=False)

    else:
        logging.debug("Invalid request method {} {}".format(request.method, request.path))
        return JsonResponse("Bad Request", status=400, safe=False)

@never_cache
def health_check(request):
    metrics.health_check.inc()
    try:
        if request.method == 'GET':
            return HttpResponse("System Functioning Normally", status=200, content_type='application/json')
        else:
            return HttpResponse("Abort", status=400, content_type='application/json')
    except Exception as e:
        return HttpResponse(e, status=200, content_type='application/json')


@never_cache
def get_new_recipe_by_id(request, id):
    try:
        logging.debug("Request Method: {}".format(request.method))
        logging.debug("Request Path: {}".format(request.path))
        metrics.get_recipe_by_id.inc()
        cache_string = str(id)
        if cache_string in cache:
            output = cache.get(cache_string)
            logging.debug("Cache Hit Success!! recipe found in cache")
            ser = RecipeSerializer(output)
            return JsonResponse(ser.data, status=200, safe=False)
        else:
            recipe_obj = Recipes.objects.get(pk=id)
            serlializer = RecipeSerializer(recipe_obj)
            logging.debug("Cache miss!! recipe not found in cache")
            cache.set(str(recipe_obj.id), recipe_obj, timeout=CACHE_TTL)
            logging.debug("Set cache success recipe")
            return JsonResponse(serlializer.data, status=200)
    except ValidationError as e:
        logging.debug("Recipe id {} Not Found".format(id))
        return JsonResponse(e, status=404, safe=False)
    except Recipes.DoesNotExist as e:
        logging.debug("Recipe {} not found".format(id))
        return JsonResponse("recipe {} not found".format(id), status=404, safe=False)


@never_cache
def get_image_by_id(request, recipe_id, image_id):
    if request.method == "GET":
        logging.debug("Request Method: {}".format(request.method))
        logging.debug("Request Path: {}".format(request.path))
        metrics.get_image_by_id.inc()
        try:
            cache_string = str(image_id)
            if (cache_string in cache and Recipes.objects.filter(pk=recipe_id).exists()):
                output = cache.get(cache_string)
                ser = ImageSerializer(output)
                logging.debug("cache hit image found in cache")
                return JsonResponse(ser.data, status=200, safe=False)
            else:
                if str(recipe_id) in cache:
                    recipe_obj = cache.get(str(recipe_id))
                    logging.debug("cache hit!! recipe found in cache")
                else:
                    recipe_obj = Recipes.objects.get(pk=recipe_id)
                    logging.debug("cache miss!! recipe not found in cache")
                    cache.set(str(recipe_obj.id), recipe_obj, timeout=CACHE_TTL)
                    logging.debug("success cache set recipe")
                image_obj = Image.objects.get(pk=image_id, recipe=recipe_obj)
                serializer = ImageSerializer(image_obj)
                cache.set(str(image_obj.id), image_obj, timeout=CACHE_TTL)
                logging.debug("success cache set image")
                return JsonResponse(serializer.data, status=200)

        except ValidationError:
            logging.debug("Image id {} or recipe id {} not found".format(image_id, recipe_id))
            return JsonResponse("Image not Found", status=404, safe=False)

        except Recipes.DoesNotExist:
            logging.debug("Recipe id {} not found".format(recipe_id))
            return JsonResponse("Image not Found", status=404, safe=False)

        except Image.DoesNotExist:
            logging.debug("Image id {} not found".format(image_id))
            return JsonResponse("Image not Found. Cannot get the requested image.", status=404, safe=False)

        except Exception as e:
            logging.debug(e)
            return JsonResponse("Unknown  Error.", status=404, safe=False)
    elif request.method == 'DELETE':
        return delete_image_by_id(request, recipe_id, image_id)

    else:
        logging.debug("Invalid request method {} {}".format(request.method, request.path))
        return HttpResponse(f"Invalid request type: {request.method}", status=403)

def delete_image_by_id(request, recipe_id, image_id):
    logging.debug("Request Method: {}".format(request.method))
    logging.debug("Request Path: {}".format(request.path))
    auth = request.headers.get('Authorization')
    metrics.delete_image.inc()
    if auth:
        auth_status = checkauth(auth)
    else:
        logging.debug("login credentials not provided")
        return JsonResponse("please provide login credentials", status=403, safe=False)
    if auth_status == 'success':
        try:
            user_obj = User.objects.get(email_address=email)
            if str(recipe_id) in cache:
                recipe_obj = cache.get(str(recipe_id))
                logging.info("cache hit!! recipe found in cache")
            else:
                recipe_obj = Recipes.objects.get(pk=recipe_id, author_id=user_obj)
                cache.set(str(recipe_obj.id), recipe_obj, timeout=CACHE_TTL)
            image_obj = Image.objects.get(pk=image_id, recipe=recipe_obj)
            # Image.objects.get(pk=image_id, recipe=recipe_obj).delete()
            image_obj.delete()
            url = image_obj.urls
            file_name = url.split('/')[-1]
            delete_image_from_s3(file_name)
            cache_string = str(image_obj.id)
            if cache_string in cache:
                cache.delete(cache_string)
                logging.debug("image delete from cache")
            logging.debug("success image deleted")
            return JsonResponse("Image Deleted Successfully", status=204, safe=False)

        except ValidationError as e:
            logging.debug(e)
            return JsonResponse("Unknown error. Nothing to delete", status=404, safe=False)

        except Image.DoesNotExist:
            logging.debug("Image {} not found".format(image_id))
            return JsonResponse("No Image found to delete", status=404, safe=False)

        except Exception as e:
            logging.debug(e)
            return JsonResponse("You are not authorized to delete this image", status=403, safe=False)

    elif auth_status == "wrong_pwd":
        return JsonResponse("Wrong Password", status=403, safe=False)

    elif auth_status == "no_user":
        return JsonResponse("User Not Found", status=404, safe=False)

    else:
        logging.debug("unauthorized")
        return JsonResponse("Unauthorized", status=403, safe=False)


def delete_image_from_s3(file_name):
    try:
        conn = S3Connection(AWS_ACCESS_KEY, AWS_SECRET_KEY)
        logging.info("success s3 connection")
        bucket = Bucket(conn, BUCKET)
        k = Key(bucket=bucket, name=file_name)
        k.delete()
        logging.info("success delete image from s3")
    except Exception as e:
        logging.debug(e)


def recipe_crud(request, id):
    auth = request.headers.get('Authorization')
    if request.method == "DELETE":
        logging.info("Request Method: {}".format(request.method))
        logging.info("Request Path: {}".format(request.path))
        metrics.delete_recipe.inc()
        if auth:
            auth_status = checkauth(auth)
        else:
            logging.debug("login credentials not provided")
            return JsonResponse("please provide login credentials", status=403, safe=False)

        if auth_status == 'success':
            try:
                user_obj = User.objects.get(email_address=email)
                # recipe_obj = Recipes.objects.get(pk=id, author_id=user_obj.id)
                Recipes.objects.get(pk=id, author_id=user_obj.id).delete()
                logging.info("success recipe deleted")
                cache_string = str(id)
                if cache_string in cache:
                    cache.delete(cache_string)
                    logging.info("recipe deleted from cache")
                return JsonResponse("Recipe Deleted Successfully", status=204, safe=False)
            except ValidationError:
                logging.debug("recipe {} not found".format(id))
                return JsonResponse("No Validate Recipe found to delete", status=404, safe=False)
            except Recipes.DoesNotExist:
                logging.debug("recipe {} not found".format(id))
                return JsonResponse("No recipe to delete.", status=404, safe=False)
            except Exception as e:
                logging.debug(e)
                return JsonResponse("You are not authorized to delete this.", status=401, safe=False)

        elif auth_status == "wrong_pwd":
            return JsonResponse("Wrong Password", status=403, safe=False)

        elif auth_status == "no_user":
            return JsonResponse("User Not Found", status=404, safe=False)

    elif request.method == 'GET':
        return get_new_recipe_by_id(request, id)

    elif request.method == 'PUT':
        return update_recipe(request, id, auth=auth)

    else:
        logging.debug("Invalid request method {} {}".format(request.method, request.path))
        return JsonResponse("Bad Request", status=400, safe=False)


def update_recipe(request, id, auth):
    logging.debug("Request Method: {}".format(request.method))
    logging.debug("Request Path: {}".format(request.path))
    metrics.update_recipe.inc()
    if auth:
        auth_status = checkauth(auth)
    else:
        logging.debug("login credentials not provided")
        return JsonResponse("please provide login credentials", status=401, safe=False)
    request_body = json.loads(request.body)
    logging.debug("Body: {}".format(request_body))
    if auth_status == 'success':
        required_params = ['cook_time_in_min', 'prep_time_in_min', 'title', 'cuisine', 'servings', 'ingredients',
                           'steps', 'nutrition_information']
        missing_keys = check_params(required_params, request_body)
        if missing_keys:
            logging.debug("missing {} in request body".format(", ".join(missing_keys)))
            return JsonResponse("missing {}".format(", ".join(missing_keys)), status=400, safe=False)
        try:
            cook_time_in_min = multipleValidator(request_body['cook_time_in_min'], 'cook_time_in_min')
            prep_time_in_min = multipleValidator(request_body['prep_time_in_min'], 'prep_time_in_min')
            title = request_body['title']
            cuisine = request_body['cuisine']
            servings = minMaxvalidators(request_body['servings'], 1, 5, 'servings')
            ingredients = uniqueValidator(request_body['ingredients'], 'ingredients')
            steps = request_body['steps']
            steps_sort = sorted(steps, key=lambda k: k['position'], reverse=True)
            nutri_info = request_body['nutrition_information']
            total_time = multipleValidator(cook_time_in_min + prep_time_in_min, 'total_time')
            for item in steps_sort:
                minValidator(item['position'], 1, 'position')
        except ValidationError as e:
            logging.debug(e)
            return HttpResponse(e, status=400, content_type='application/json')

        user = User.objects.get(email_address=email)

        try:
            cache_string = str(id)
            if cache_string in cache:
                recipe = cache.get(cache_string)
                logging.info("cache hit!! recipe found in cache")
            else:
                recipe = Recipes.objects.get(pk=id)
                logging.info("cache miss!!! recipe not found in cache")
            if not (recipe.author_id == user):
                logging.debug("Not authorized to update recipe")
                return JsonResponse("You are not authorized to update this recipe", status=401, safe=False)
            else:
                nutrition_object = recipe.nutrition_information

                nutrition_object.calories = nutri_info['calories']
                nutrition_object.cholesterol_in_mg = nutri_info['cholesterol_in_mg']
                nutrition_object.sodium_in_mg = nutri_info['sodium_in_mg']
                nutrition_object.carbohydrates_in_grams = nutri_info['carbohydrates_in_grams']
                nutrition_object.protein_in_grams = nutri_info['protein_in_grams']
                nutrition_object.save()

                steps_object = OrderedList.objects.filter(recipe=recipe.id)
                steps_object.delete()

                for item in steps:
                    order_obj = OrderedList(position=item['position'], items=item['items'], recipe=recipe)
                    order_obj.save()

                recipe.cook_time_in_min = cook_time_in_min
                recipe.prep_time_in_min = prep_time_in_min
                recipe.total_time_in_min = total_time
                recipe.title = title
                recipe.cuisine = cuisine
                recipe.servings = servings
                recipe.ingredients = ingredients
                recipe.nutrition_information = nutrition_object

                recipe.save()
                logging.info("Success recipe updated")
                serial = RecipeSerializer(recipe)
                cache.set(str(recipe.id), recipe, timeout=CACHE_TTL)
                logging.info("cache set with new recipe")
                return JsonResponse(serial.data, status=200)
        except ValidationError:
            logging.debug("Recipe {} not found".format(id))
            return JsonResponse("Recipe not Found", status=404, safe=False)
        except Recipes.DoesNotExist:
            logging.debug("Recipe {} not found".format(id))
            return JsonResponse("Recipe not Found", status=404, safe=False)

    elif auth_status == "wrong_pwd":
        return JsonResponse("Wrong Password", status=403, safe=False)
    elif auth_status == "no_user":
        return JsonResponse("User Not Found", status=404, safe=False)


def encryptpwd(pwd):
    salt = bcrypt.gensalt()
    encoded_pwd = pwd.encode('utf-8')
    hash_pwd = bcrypt.hashpw(encoded_pwd, salt).decode('utf-8')
    return hash_pwd


def decryptpwd(pwd, hashed_pwd):
    return bcrypt.checkpw(pwd, hashed_pwd.encode('utf-8'))


def checkauth(auth):
    global email
    encodedvalue = auth.split(" ")
    authvalue = encodedvalue[1]
    decoded_value = base64.b64decode(authvalue).decode('utf-8')
    creds = decoded_value.split(":")
    email = creds[0]
    pwd = creds[1]
    if User.objects.filter(email_address=email).exists():
        user_obj = User.objects.get(email_address=email)
        if decryptpwd(pwd.encode('utf-8'), user_obj.password):
            logging.info("Login Successful")
            return "success"
        else:
            logging.debug("Wrong password !! login failed")
            return "wrong_pwd"
    else:
        logging.debug("email not registered or wrong email address")
        return "no_user"


def check_params(req_params, req_body):
    keys = req_body.keys()
    missing_keys = []
    for item in req_params:
        if item not in keys:
            missing_keys.append(item)
            continue
        elif not req_body[item]:
            missing_keys.append(item)
    return missing_keys

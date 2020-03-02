import json
import boto3
import random
import bcrypt
import base64
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
import os
import logging
import redis
from django.views.decorators.cache import never_cache
import uuid


email = ""
logging.basicConfig(format='%(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)
# BUCKET = os.environ.get("BUCKET_NAME")
# AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
# AWS_SECRET_KEY = os.environ.get("SECRET_ACCESS_KEY_ID")

BUCKET = 'dev-csye7374-django-backend-recipe-management'
AWS_ACCESS_KEY = 'AKIAY2TPSKG7XT2RWQOM'
AWS_SECRET_KEY = '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'

CACHE_TTL = getattr(settings, 'CACHE_TTL', DEFAULT_TIMEOUT)
conn = False

# Connect to our Redis instance
try:
    REDIS_CONN_POOL_1 = settings.REDIS_CONN_POOL_1
    conn = redis.Redis(connection_pool=REDIS_CONN_POOL_1)
    logging.debug(conn)

except Exception as connection_exception:
    logging.debug(connection_exception)


def user(request):
    if request.method == 'POST':
        request_body = json.loads(request.body)
        if not request_body:
            return JsonResponse("No body Provided", status=204, safe=False)
        required_params = ['first_name', 'last_name', 'password', 'email_address']
        missing_keys = check_params(required_params, request_body)
        if missing_keys:
            return HttpResponse("Missing {}".format(", ".join(missing_keys)), status=400,
                                content_type="application/json")

        first_name = request_body['first_name']
        last_name = request_body['last_name']
        email = request_body['email_address']
        pwd = request_body['password']
        try:
            validate_email(email)
        except ValidationError:
            return HttpResponse("Invalid Email", status=400, content_type="application/json")
        try:
            validate = RegexValidator(regex='^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$')
            validate(pwd)
        except ValidationError:
            return HttpResponse("Enter a Strong Password", status=400, content_type="application/json")

        encrypt_pwd = encryptpwd(pwd)
        new_user = User(first_name=first_name, last_name=last_name, password=encrypt_pwd, email_address=email)
        ser = UserSerializer(new_user)
        try:
            new_user.save()
        except IntegrityError as e:
            return HttpResponse("User already exists", status=400, content_type="application/json")
        return JsonResponse(ser.data, status=201)
    else:
        return HttpResponse("Invalid Request method", status=400, content_type="application/json")


def update_user(request):
    if request.method == 'PUT':
        auth = request.headers.get('Authorization')
        if auth:
            auth_status = checkauth(auth)
        else:
            return JsonResponse("please provide login credentials", status=403, safe=False)
        request_body = json.loads(request.body)
        if not request_body:
            return JsonResponse("No body Provided", status=204, safe=False)
        if auth_status == 'success':
            required_params = ['first_name', 'last_name', 'password', 'email_address']
            missing_keys = check_params(required_params, request_body)
            if missing_keys:
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
                    return HttpResponse("Email address cannot be updated", status=400, content_type='application/json')
            if changed:
                ser = UserSerializer(user_obj)
                user_obj.save()
                return JsonResponse(ser.data, status=200)
            else:
                return JsonResponse("No changes to update", status=200, safe=False)
        elif auth_status == "wrong_pwd":
            return JsonResponse("Wrong Password", status=403, safe=False)
        elif auth_status == "no_user":
            return JsonResponse("User Not Found", status=404, safe=False)

    elif request.method == 'GET':
        return get_user(request)

    else:
        return JsonResponse("Invalid request method", status=400, safe=False)


def get_user(request):
    auth = request.headers.get('Authorization')
    if auth:
        auth_status = checkauth(auth)
    else:
        return JsonResponse("please provide login credentials", status=403, safe=False)

    if auth_status == 'success':
        user_obj = User.objects.get(email_address=email)
        serialize = GetUserSerializer(user_obj)
        return JsonResponse(serialize.data, status=200)

    elif auth_status == 'wrong_pwd':
        return JsonResponse("Wrong Password", status=403, safe=False)

    elif auth_status == 'no_user':
        return JsonResponse("User Not Found", status=404, safe=False)


def create_recipe(request):
    if request.method == "POST":
        auth = request.headers.get('Authorization')
        if auth:
            auth_status = checkauth(auth)
        else:
            return JsonResponse("please provide login credentials", status=403, safe=False)
        request_body = json.loads(request.body)
        if auth_status == 'success':
            required_params = ['cook_time_in_min', 'prep_time_in_min', 'title', 'cuisine', 'servings', 'ingredients',
                               'steps', 'nutrition_information']
            missing_keys = check_params(required_params, request_body)
            if missing_keys:
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
                return HttpResponse(e, status=400, content_type='application/json')

            author = User.objects.get(email_address=email)

            nutrition_obj = NutritionalInformation(calories=nutri_info['calories'],
                                                   cholesterol_in_mg=nutri_info['cholesterol_in_mg'],
                                                   sodium_in_mg=nutri_info['sodium_in_mg'],
                                                   carbohydrates_in_grams=nutri_info['carbohydrates_in_grams'],
                                                   protein_in_grams=nutri_info['protein_in_grams'])
            nutrition_obj.save()

            recipe_obj = Recipes(author_id=author, cook_time_in_min=cook_time_in_min, prep_time_in_min=prep_time_in_min,
                                 total_time_in_min=total_time, title=title, cuisine=cuisine, servings=servings,
                                 ingredients=ingredients, nutrition_information=nutrition_obj)
            recipe_obj.save()

            for item in steps_sort:
                order_obj = OrderedList(position=item['position'], items=item['items'], recipe=recipe_obj)
                order_obj.save()

            ser = RecipeSerializer(recipe_obj)
            cache.set(str(recipe_obj.id), str(ser.data), timeout=CACHE_TTL)
            return JsonResponse(ser.data, status=201)

        elif auth_status == "wrong_pwd":
            return JsonResponse("Wrong Password", status=403, safe=False)

        elif auth_status == "no_user":
            return JsonResponse("User Not Found", status=404, safe=False)

    else:
        return JsonResponse("Invalid request method", status=400, safe=False)


def upload_image(request, id):
    region = 'us-east-1'
    try:
        if request.method == "POST":
            auth = request.headers.get('Authorization')
            file = request.FILES['file']
            auth_status = checkauth(auth)
            try:
                if auth_status == "success":
                    user = User.objects.get(email_address=email)
                    recipe_obj = Recipes.objects.get(pk=id)
                    if not (recipe_obj.author_id == user):
                        return JsonResponse("You are not authorized to update this recipe", status=401, safe=False)
                    else:
                        file_name = file.name
                        file_name = file_name + str(uuid.uuid4())
                        s3_bucket = BUCKET
                        s3_client = boto3.client(
                            's3',
                            aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_KEY)
                        s3_client.upload_fileobj(file, s3_bucket, file_name)
                        s3_url = f"https://s3-{region}.amazonaws.com/{s3_bucket}/{file_name}"

                        img_object = Image(urls=s3_url, recipe=recipe_obj)
                        img_object.save()
                        ser = ImageSerializer(img_object)
                        serialize = RecipeSerializer(recipe_obj)
                        cache.set(str(recipe_obj.id), str(serialize.data), timeout=CACHE_TTL)
                    return JsonResponse(ser.data, status=200)

            except Recipes.DoesNotExist:
                return JsonResponse("No recipe Found", status=404, safe=False)

            except ValidationError:
                return JsonResponse("Recipe not Found", status=404, safe=False)

            except Exception as e:
                return JsonResponse("Permission denied", status=403, safe=False)

    except Exception as e:
        print(e)


@never_cache
def get_newest_recipe(request):

    if request.method == 'GET':

        try:
            recipe_obj = Recipes.objects.latest('updated_ts')
            cache_string = str(recipe_obj.id)

            if cache_string in cache:
                output = cache.get(str(recipe_obj.id))
                logging.debug(output)
                return JsonResponse(output, status=200, safe=False, json_dumps_params={'indent': 4})

            else:
                recipe_obj = Recipes.objects.latest('updated_ts')
                serialize = RecipeSerializer(recipe_obj)
                logging.debug(serialize.data)
                cache.set(str(recipe_obj.id), str(serialize.data), timeout=CACHE_TTL)
                return JsonResponse(serialize.data, status=200, safe=False, json_dumps_params={'indent': 4})

        except Recipes.DoesNotExist:
            return JsonResponse("Recipe not Found", status=404, safe=False)

        except ValidationError:
            return JsonResponse("Recipe not Found", status=404, safe=False)

        except ValueError:
            return JsonResponse('Recipe not found', status=404, safe=False)

        except Exception as e:
            print(e)

    else:
        return JsonResponse("Bad Request", status=400, safe=False)


def redis_health_check(request):
    if request.method == 'GET':
        try:
            host = os.environ.get("redisHost")
            port = os.environ.get("redisPort")
            password = os.environ.get("redisPass")
            conn = redis.StrictRedis(host=host, port=port, password=password)
            if conn.ping():
                return HttpResponse("Redis Connected", status=200, content_type='application/json')
            else:
                return HttpResponse("Redis Connection failed", status=400, content_type='application/json')
        except Exception as e:
            return HttpResponse(e, status=400, content_type='application/json')


@never_cache
def get_random_recipe(request):
    if request.method == 'GET':

        try:
            recipe_obj = Recipes.objects.all()
            random_item = random.choice(recipe_obj)
            cache_string = str(random_item.id)

            if cache_string in cache:
                output = cache.get(str(random_item.id))
                logging.debug(output)
                return JsonResponse(output, status=200, safe=False, json_dumps_params={'indent': 4})

            else:
                recipe_obj = Recipes.objects.all()
                random_item = random.choice(recipe_obj)
                serialize = RecipeSerializer(random_item)
                return JsonResponse(serialize.data, status=200, safe=False, json_dumps_params={'indent': 4})

        except Recipes.DoesNotExist:
            return JsonResponse("Recipe not Found", status=404, safe=False)

    else:
        return JsonResponse("Bad Request", status=400, safe=False)


def health_check(request):
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
        recipe_obj = Recipes.objects.get(pk=id)
        cache_string = str(recipe_obj.id)
        if cache_string in cache:
            output = cache.get(cache_string)
            logging.debug(output)
            return JsonResponse(output, status=200, safe=False, json_dumps_params={'indent': 4})
        else:
            recipe_obj = Recipes.objects.get(pk=id)
            serlializer = RecipeSerializer(recipe_obj)
            logging.debug(serlializer.data)
            cache.set(str(recipe_obj.id), str(serlializer.data), timeout=CACHE_TTL)
            return JsonResponse(serlializer.data, status=200)

    except ValidationError:
        return JsonResponse("Recipe not Found", status=404, safe=False)

    except Recipes.DoesNotExist:
        return JsonResponse("Recipe not Found", status=404, safe=False)

    except ValueError:
        return JsonResponse('Recipe not found', status=404, safe=False)

    except Exception as e:
        print(e)


@never_cache
def get_image_by_id(request, recipe_id, image_id):

    if request.method == "GET":

        try:
            recipe_obj = Recipes.objects.get(pk=recipe_id)
            image_obj = Image.objects.get(pk=image_id, recipe=recipe_obj)
            cache_string = str(image_obj.id)

            if cache_string in cache:
                output = cache.get(cache_string)
                return JsonResponse(output, status=200, safe=False, json_dumps_params={'indent': 4})

            else:
                recipe_obj = Recipes.objects.get(pk=recipe_id)
                image_obj = Image.objects.get(pk=image_id, recipe=recipe_obj)
                serializer = ImageSerializer(image_obj)
                cache.set(str(image_obj.id), str(serializer.data), timeout=CACHE_TTL)
                return JsonResponse(serializer.data, status=200)

        except ValidationError:
            return JsonResponse("Image not Found", status=404, safe=False)

        except Recipes.DoesNotExist:
            return JsonResponse("Image not Found", status=404, safe=False)

        except Image.DoesNotExist:
            return JsonResponse("Image not Found. Cannot get the requested image.", status=404, safe=False)

        except Exception:
            return JsonResponse("Unknown  Error.", status=404, safe=False)

    elif request.method == 'POST':
        return HttpResponse(f"Invalid request type: {request.method}", status=403)

    elif request.method == 'PUT':
        return HttpResponse(f"Invalid request type: {request.method}", status=403)

    elif request.method == 'DELETE':
        return delete_image_by_id(request, recipe_id, image_id)


def delete_image_by_id(request, recipe_id, image_id):
    auth = request.headers.get('Authorization')

    if request.method == "DELETE":

        if auth:
            auth_status = checkauth(auth)

        else:
            return JsonResponse("please provide login credentials", status=403, safe=False)

        if auth_status == 'success':
            try:
                user_obj = User.objects.get(email_address=email)
                recipe_obj = Recipes.objects.get(pk=recipe_id, author_id=user_obj)
                image_obj = Image.objects.get(pk=image_id, recipe=recipe_obj)
                Image.objects.get(pk=image_id, recipe=recipe_obj).delete()
                url = image_obj.urls
                file_name = url.split('/')[-1]
                delete_image_from_s3(file_name)
                cache_string = str(recipe_obj.id)
                if cache_string in cache:
                    cache.delete(cache_string)
                return JsonResponse("Image Deleted Successfully", status=204, safe=False)

            except ValidationError:
                return JsonResponse("Unknown error. Nothing to delete", status=404, safe=False)

            except Image.DoesNotExist:
                return JsonResponse("No Image found to delete", status=404, safe=False)

            except Exception:
                return JsonResponse("You are not authorized to delete this image", status=403, safe=False)

        elif auth_status == "wrong_pwd":
            return JsonResponse("Wrong Password", status=403, safe=False)

        elif auth_status == "no_user":
            return JsonResponse("User Not Found", status=404, safe=False)

        else:
            return JsonResponse("Unauthorized", status=403, safe=False)


def delete_image_from_s3(file_name):
    try:
        conn = S3Connection(AWS_ACCESS_KEY, AWS_SECRET_KEY)
        bucket = Bucket(conn, BUCKET)
        k = Key(bucket=bucket, name=file_name)
        k.delete()

    except Exception as e:
        print(e)


def recipe_crud(request, id):
    auth = request.headers.get('Authorization')
    if request.method == "DELETE":
        if auth:
            auth_status = checkauth(auth)

        else:
            return JsonResponse("please provide login credentials", status=403, safe=False)

        if auth_status == 'success':
            try:
                user_obj = User.objects.get(email_address=email)
                recipe_obj = Recipes.objects.get(pk=id, author_id=user_obj.id)
                Recipes.objects.get(pk=id, author_id=user_obj.id).delete()
                cache_string = str(recipe_obj.id)
                if cache_string in cache:
                    cache.delete(cache_string)
                return JsonResponse("Recipe Deleted Successfully", status=204, safe=False)
            except ValidationError:
                return JsonResponse("No Validate Recipe found to delete", status=404, safe=False)
            except Recipes.DoesNotExist:
                return JsonResponse("No recipe to delete.", status=404, safe=False)
            except Exception:
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
        return JsonResponse("Bad Request", status=400, safe=False)


def update_recipe(request, id, auth):
    if auth:
        auth_status = checkauth(auth)
    else:
        return JsonResponse("please provide login credentials", status=401, safe=False)
    request_body = json.loads(request.body)
    if auth_status == 'success':
        required_params = ['cook_time_in_min', 'prep_time_in_min', 'title', 'cuisine', 'servings', 'ingredients',
                           'steps', 'nutrition_information']
        missing_keys = check_params(required_params, request_body)
        if missing_keys:
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
            return HttpResponse(e, status=400, content_type='application/json')

        user = User.objects.get(email_address=email)

        try:
            recipe = Recipes.objects.get(pk=id)
            cache_string = str(recipe.id)
            if cache_string in cache:
                cache.delete(cache_string)
            if not (recipe.author_id == user):
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
                serial = RecipeSerializer(recipe)
                cache.set(str(recipe.id), str(serial.data), timeout=CACHE_TTL)
                return JsonResponse(serial.data, status=200)
        except ValidationError:
            return JsonResponse("Recipe not Found", status=404, safe=False)
        except Recipes.DoesNotExist:
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
            return "success"
        else:
            return "wrong_pwd"
    else:
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

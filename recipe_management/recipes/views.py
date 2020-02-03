import json
import bcrypt
import base64
from django.db import IntegrityError
from .serializers import UserSerializer, RecipeSerializer, GetUserSerializer
from django.core.exceptions import ValidationError
from django.core.validators import validate_email, RegexValidator
from django.http import HttpResponse, JsonResponse
from .validators import multipleValidator, minMaxvalidators, minValidator, uniqueValidator
from .models import User, Recipes, OrderedList, NutritionalInformation

email = ""


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
                elif item == 'password' and not (decryptpwd(request_body['password'].encode('utf-8'), user_obj.password)):
                    encrypted_pwd = encryptpwd(request_body['password'])
                    user_obj.password = encrypted_pwd
                    changed = True
                    continue
                elif request_body['email_address'] != user_obj.email_address:
                    return HttpResponse("Email address cannot be updated", status=400)
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
        auth = request.headers.get('Authorization')
        if auth:
            auth_status = checkauth(auth)
        else:
            return JsonResponse("please provide login credentials", status=403, safe=False)
        response = get_auth_status(auth_status)
        return response
    else:
        return JsonResponse("Invalid request method", status=400, safe=False)


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

            for item in steps:
                order_obj = OrderedList(position=item['position'], items=item['items'], recipe=recipe_obj)
                order_obj.save()

            ser = RecipeSerializer(recipe_obj)

            return JsonResponse(ser.data, status=201)

        elif auth_status == "wrong_pwd":
            return JsonResponse("Wrong Password", status=403, safe=False)
        elif auth_status == "no_user":
            return JsonResponse("User Not Found", status=404, safe=False)
    else:
        return JsonResponse("Invalid request method", status=400, safe=False)


def get_newest_recipe(request):
    if request.method == 'GET':
        try:
            recipe_obj = Recipes.objects.latest('updated_ts')
            serialize = RecipeSerializer(recipe_obj)
            return JsonResponse(serialize.data, status=200)
        except Recipes.DoesNotExist:
            return JsonResponse("Recipe not Found", status=404, safe=False)

    elif request.method == 'POST' or request.method == 'DELETE' or request.method == 'PUT':
        return JsonResponse("Bad Request", status=400, safe=False)


def get_new_recipe_by_id(request, id):
    if request.method == "GET":
        try:
            recipe_obj = Recipes.objects.get(pk=id)
            serlializer = RecipeSerializer(recipe_obj)
            return JsonResponse(serlializer.data, status=200)
        except ValidationError:
            return JsonResponse("Recipe not Found", status=404, safe=False)
        except Recipes.DoesNotExist:
            return JsonResponse("Recipe not Found", status=404, safe=False)

    elif request.method == 'POST' or request.method == 'DELETE' or request.method == 'PUT':
        return JsonResponse("Bad Request", status=400, safe=False)


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


def get_auth_status(auth_status):
    if auth_status == 'success':
        user_obj = User.objects.get(email_address=email)
        serialize = GetUserSerializer(user_obj)
        return JsonResponse(serialize.data, status=200)

    elif auth_status == 'wrong_pwd':
        return JsonResponse("Wrong Password", status=403, safe=False)

    elif auth_status == 'no_user':
        return JsonResponse("User Not Found", status=404, safe=False)


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

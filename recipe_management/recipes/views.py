import json
import bcrypt
import base64
from django.db import IntegrityError
from .serializers import UserSerializer
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.validators import RegexValidator
from django.http import HttpResponse
from django.http import JsonResponse
from .models import User

email = ""


def user(request):
    if request.method == 'POST':
        request_body = json.loads(request.body)
        required_params = ['first_name', 'last_name', 'password', 'email_address']
        keys = request_body.keys()
        missing_keys = []
        for item in required_params:
            if item not in keys:
                missing_keys.append(item)
        if missing_keys:
            return HttpResponse("Missing {}".format(", ".join(missing_keys)), status=400, content_type="application/json")

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
        auth_status = checkauth(auth)
        request_body = json.loads(request.body)
        if auth_status == 'success':
            # allowed_params = ['first_name', 'last_name', 'password']
            user_obj = User.objects.get(email_address=email)
            for item in request_body.keys:
                if item == 'first_name':
                    user_obj.first_name = request_body['first_name']
                if item == 'last_name':
                    user_obj.last_name = request_body['last_name']
                if item == 'password':
                    user_obj.password == request_body['password']
                else:
                    return HttpResponse("{} cannot be updated".format(item), status=400)
            user_obj.save()
            return HttpResponse("Successfully updated User", status=200)
    else:
        return JsonResponse("Invalid request method", status=400, safe=False)


def encryptpwd(pwd):
    salt = bcrypt.gensalt()
    encoded_pwd = pwd.encode('utf-8')
    hash_pwd = bcrypt.hashpw(encoded_pwd, salt)
    return hash_pwd


def decryptpwd(pwd, hashed_pwd):
    return bcrypt.checkpw(pwd, hashed_pwd)


def checkauth(auth):
    global email
    encodedvalue = auth.split(" ")
    authvalue = encodedvalue[1]
    decoded_value = base64.b64decode(authvalue).decode('utf-8')
    creds = decoded_value.split(":")
    email = creds[0]
    pwd = creds[1]
    if (User.objects.filter(email_address=email).exists()):
        user_obj = user.objects.get(email_address=email)
        if (decryptpwd(pwd,user_obj.password)):
            return "success"
        else:
            return "wrong_pwd"
    else:
        return "no_user"





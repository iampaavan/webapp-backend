import json
import bcrypt
import base64
from django.db import IntegrityError
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.validators import RegexValidator
from django.http import HttpResponse
from .models import User

def user(request):
    request_body = json.loads(request.body)
    required_params = ['first_name', 'last_name', 'password', 'email_address']
    keys = request_body.keys()
    missing_keys = []
    for item in required_params:
        if item not in keys:
            missing_keys.append(item)
    if missing_keys:
        return HttpResponse("Missing {}".format(", ".join(missing_keys)), status=400)

    first_name = request_body['first_name']
    last_name = request_body['last_name']
    email = request_body['email_address']
    pwd = request_body['password']
    try:
        validate_email(email)
    except ValidationError:
        return HttpResponse("Invalid Email", status=400)
    try:
        validate = RegexValidator(regex='[A-Za-z0-9@#$%^&+=]{8,}')
        validate(pwd)
    except ValidationError:
        return HttpResponse("Enter a Strong Password", status=400)

    encrypt_pwd = encryptpwd(pwd)
    new_user = User(first_name=first_name, last_name=last_name, password=encrypt_pwd, email_address=email)
    try:
        new_user.save()
    except IntegrityError as e:
        return HttpResponse("User already exists", status=400)
    return HttpResponse(status=201)

def update_user(request):
    auth = request.headers.get('Authorization')
    



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
    if (user.objects.filter(username=email).exists()):
        user_obj = user.objects.get(username=email)
        if(user_obj.password == pwd):
            return "success"
        else:
            return "wrong_pwd"
    else:
        return "no_user"





from django.core.exceptions import ValidationError

def multipleValidator(value, str):

    if value % 5 == 0:
        return value
    else:
        raise ValidationError("{} should be multiple of 5".format(str))

def minMaxvalidators(value, min, max, str):
    if value < min or value > max:
        raise ValidationError("{} should be minimum {} and maximum {}".format(str, min, max))
    else:
        return value

def minValidator(value, min , str):
    if value < min:
        raise ValidationError("{} should be greater than {}".format(str , min))
    else:
        return value

def uniqueValidator(value, str):
    if (len(set(value)) == len(value)):
        return value
    else:
        raise ValidationError("{} should have unique items".format(str))


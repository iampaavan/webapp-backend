from prometheus_client import Counter

user_created = Counter('user_created', "/v1/user --> create user")
user_updated = Counter('user_updated', "/v1/user/self --> update user")
get_user = Counter('get_user', "/v1/user/self --> get user details")
recipe_created = Counter('recipe_created', "/v1/recipe/ --> create recipe")
image_uploaded = Counter('image_uploaded', "/recipe/id/image --> upload image")
newest_recipe = Counter('newest_recipe', "/v1/recipes --> get newest recipe")
random_recipe = Counter('random_recipe', "/v1/get/random/recipe --> get a random recipe")
get_recipe_by_id = Counter('get_recipe_by_id', "/v1/get/random/recipe")
get_image_by_id = Counter('get_image_by_id', "get the image attached to recipe by id")
delete_image = Counter('delete_image_by_id', "delete image attached to recipe by id")
delete_recipe = Counter('delete_recipe', "delete recipe by id")
update_recipe = Counter('update_recipe', "update recipe by id")
redis_health = Counter('redis_health', 'health check for redis connectivity')
health_check = Counter('app_health', "application health check")





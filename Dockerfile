# pull official base image
FROM python:3 as build-stage

# set work directory
WORKDIR /usr/src/app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
RUN pip install --upgrade pip
COPY ./requirements.txt /usr/src/app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
# copy project
COPY . /usr/src/app/

FROM nginx:1.15
COPY --from=build-stage /usr/src/app/recipe_management.conf /etc/nginx/sites-available/recipe_management.conf
RUN ln -s /etc/nginx/sites-available/recipe_management.conf /etc/nginx/sites-enabled
RUN service nginx restart

FROM build-stage as build2
RUN chmod 777 entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]




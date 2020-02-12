# pull official base image
FROM python:3

# set work directory
WORKDIR /usr/src/app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1


# install dependencies
RUN pip install --upgrade pip
COPY ./requirements.txt /usr/src/app/requirements.txt
RUN pip install -r requirements.txt
RUN curl -L "https://github.com/docker/compose/releases/download/1.25.3/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

RUN docker-compose --version

# copy project
COPY . /usr/src/app/

EXPOSE 8080
EXPOSE 5432

RUN docker-compose up -d --build
RUN docker-compose exec web python manage.py migrate --noinput

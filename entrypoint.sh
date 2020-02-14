#!/bin/bash
cd recipe_management
exec gunicorn recipe_management.wsgi:application --bind 0.0.0.0:8000
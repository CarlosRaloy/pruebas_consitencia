#!/bin/bash
DJANGODIR=$(dirname $(cd `dirname $0` && pwd))
echo ".: Directory by project :."
echo $DJANGODIR
DJANGO_SETTINGS_MODULE=settings.settings
cd $DJANGODIR
source venv/bin/activate
export DJANGO_SETTINGS_MODULE=$DJANGO_SETTINGS_MODULE
exec python main.py runserver 0:8036

# Alternativa para producción (waitress ya está en requirements.txt):
#exec waitress-serve --listen=0.0.0.0:8036 main:application

# -*- coding: utf-8 -*-
# Core Django imports
from django.conf.urls import url

# Imports from your apps
from api import views
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    url(r'^init$', csrf_exempt(views.init)),
    url(r'^create$', csrf_exempt(views.create)),
    url(r'^activate$', csrf_exempt(views.activate)),
    url(r'^sign$', csrf_exempt(views.sign)),
    url(r'^reset_pin$', csrf_exempt(views.reset_pin)),
    url(r'^deactivate$', csrf_exempt(views.deactivate)),
    url(r'^update_cert$', csrf_exempt(views.update_cert)),
]

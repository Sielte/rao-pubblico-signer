# -*- coding: utf-8 -*-
import hmac
import logging
import os
import random

from api.models import User

LOG = logging.getLogger(__name__)


def generate_pin():
    pin = ''
    for x in range(6):
        pin += str(random.randint(0, 9))
    return pin


def check_authtoken(username, parameter, hmac_params):
    user = User.objects.filter(username=username.upper()).last()
    if user:
        try:
            message = username + parameter
            calculated_hmac = hmac.new(user.pin.encode(), message.encode(), "SHA256").hexdigest()
            if str(hmac_params).upper() == str(calculated_hmac).upper():
                return True
        except Exception as e:
            LOG.error("Exception: {}".format(str(e)))
    return False


def check_pin(username, hmac_params):
    user = User.objects.filter(username=username.upper()).last()
    if user:
        try:
            calculated_hmac = hmac.new(user.pin.encode(), username.encode(), "SHA256").hexdigest()
            if str(hmac_params).upper() == str(calculated_hmac).upper():
                return True
        except Exception as e:
            LOG.error("Exception: {}".format(str(e)))
    return False


def generate_file_name():
    file_name = "".join(
        [random.choice("ABCDEFGHIJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789") for i in range(16)]) + ".pem"
    while os.path.exists(file_name):
        file_name = "".join(
            [random.choice("ABCDEFGHIJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789") for i in
             range(16)]) + ".pem"
    return file_name

# -*- coding: utf-8 -*-
import datetime
import logging
from django.http import JsonResponse
from api.enumclass import StatusCode, RoleTag
from api.models import User
from api.utils import check_authtoken, check_pin

LOG = logging.getLogger(__name__)


def auth_admin_required(function):
    """
    Permette di limitare l'accesso ad un utenza ADMIN
    """

    def decorator(function):
        def onCall(request, *args, **kwargs):
            authToken = None
            try:
                authToken = request.META.get('HTTP_AUTHORIZATION', None)
                username = request.META.get('HTTP_USERNAME', None)
                if not authToken or not username:
                    LOG.error("Parametri assenti")
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                user = User.objects.filter(username=username.upper(), status=True, role=RoleTag.ADMIN.value).last()
                if not user:
                    LOG.error('Utente non trovato Username: {}'.format(str(username.upper())))
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                if check_pin(username, str(authToken)):
                    return function(request, *args, **kwargs)
            except Exception as e:
                LOG.error(
                    'Authorization Header non presente o non valido. AuthToken: {} - Errore: {}'.format(str(authToken),
                                                                                                        str(e)))
            return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})

        return onCall

    return decorator(function)


def auth_api_required(function):
    """
    Permette di limitare l'accesso ad un utenza generica
    """

    def decorator(function):
        def onCall(request, *args, **kwargs):
            authToken = None
            try:
                authToken = request.META.get('HTTP_AUTHORIZATION', None)
                username = request.META.get('HTTP_USERNAME', None)
                if not authToken or not username:
                    LOG.error("Parametri assenti")
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                user = User.objects.filter(username=username.upper()).first()
                if not user:
                    LOG.error('Utente non trovato Username: {}'.format(str(username.upper())))
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                if check_pin(username, str(authToken)):
                    return function(request, *args, **kwargs)
            except Exception as e:
                LOG.error(
                    'Authorization Header non presente o non valido. AuthToken: {} - Errore: {}'.format(str(authToken),
                                                                                                        str(e)))
            return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})

        return onCall

    return decorator(function)


def status_active_required(function):
    """
    Permette di limitare l'accesso ad un utenza attiva
    """

    def decorator(function):
        def onCall(request, *args, **kwargs):
            username = None
            try:
                username = request.META.get('HTTP_USERNAME', None)
                if not username:
                    LOG.error("Parametri assenti")
                    return JsonResponse(
                        {'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                user = User.objects.filter(username=username.upper(), status=True).first()
                if not user:
                    LOG.error('Utente non trovato Username: {}'.format(str(username.upper())))
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                return function(request, *args, **kwargs)
            except Exception as e:
                LOG.error('Username non attivo: {} - Errore: {}'.format(str(username), str(e)))
            return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})

        return onCall

    return decorator(function)


def auth_create_api_required(function):
    """
    Permette di limitare l'accesso ad un utenza ADMIN
    """

    def decorator(function):
        def onCall(request, *args, **kwargs):
            authToken = None
            try:
                authToken = request.META.get('HTTP_AUTHORIZATION', None)
                username = request.META.get('HTTP_USERNAME', None)
                new_username = request.POST.get('username', None)
                if not authToken or not username or not new_username:
                    LOG.error("Parametri assenti")
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                user = User.objects.filter(username=username.upper(), status=True, role=RoleTag.ADMIN.value).last()
                if not user:
                    LOG.error('Utente non trovato Username: {}'.format(str(username.upper())))
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                if check_authtoken(username, new_username, str(authToken)):
                    user.failureCounter = 0
                    user.save()
                    return function(request, *args, **kwargs)
                else:
                    user.failureCounter += 1
                    user.failureTimestamp = datetime.datetime.utcnow()
                    if user.failureCounter == 3:
                        user.status = False
                    user.save()
                    if not user.status:
                        LOG.error('Numero di tentativi massimo raggiunto. SO disabilitato Username: {}'.format(
                            str(username.upper())))
                        return JsonResponse(
                            {'statusCode': StatusCode.USER_DISABLED.value, 'message': 'Username disabilitata'})
            except Exception as e:
                LOG.error(
                    'Authorization Header non presente o non valido. AuthToken: {} - Errore: {}'.format(str(authToken),
                                                                                                        str(e)))
            return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})

        return onCall

    return decorator(function)


def auth_activate_api_required(function):
    """
    Permette di limitare l'accesso ad un utenza generica
    """

    def decorator(function):
        def onCall(request, *args, **kwargs):
            authToken = None
            try:
                authToken = request.META.get('HTTP_AUTHORIZATION', None)
                username = request.META.get('HTTP_USERNAME', None)
                newPin = request.POST.get('new_pin', None)
                if not authToken or not username or not newPin:
                    LOG.error("Parametri assenti")
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                user = User.objects.filter(username=username.upper()).first()
                if not user:
                    LOG.error('Utente non trovato Username: {}'.format(str(username.upper())))
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                if check_authtoken(username, newPin, str(authToken)):
                    return function(request, *args, **kwargs)
            except Exception as e:
                LOG.error(
                    'Authorization Header non presente o non valido. AuthToken: {} - Errore: {}'.format(str(authToken),
                                                                                                        str(e)))
            return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})

        return onCall

    return decorator(function)


def auth_sign_api_required(function):
    """
    Permette di limitare l'accesso ad un utenza generica
    """

    def decorator(function):
        def onCall(request, *args, **kwargs):
            authToken = None
            try:
                authToken = request.META.get('HTTP_AUTHORIZATION', None)
                username = request.META.get('HTTP_USERNAME', None)
                payload = request.POST.get('payload', None)
                if not authToken or not username or not payload:
                    LOG.error("Parametri assenti")
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                user = User.objects.filter(username=username.upper(), status=True, role=RoleTag.OPERATOR.value).first()
                if not user:
                    LOG.error('Utente non trovato Username: {}'.format(str(username.upper())))
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                if check_authtoken(username, payload, str(authToken)):
                    user.failureCounter = 0
                    user.save()
                    return function(request, *args, **kwargs)
                else:
                    user.failureCounter += 1
                    user.failureTimestamp = datetime.datetime.utcnow()
                    if user.failureCounter == 3:
                        user.status = False
                    user.save()
                    if not user.status:
                        LOG.error('Numero di tentativi massimo raggiunto. Utente disabilitato Username: {}'.format(
                            str(username.upper())))
                        return JsonResponse(
                            {'statusCode': StatusCode.USER_DISABLED.value, 'message': 'Username disabilitata'})
            except Exception as e:
                LOG.error(
                    'Authorization Header non presente o non valido. AuthToken: {} - Errore: {}'.format(str(authToken),
                                                                                                        str(e)))
            return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})

        return onCall

    return decorator(function)


def localhost_required(function):
    """
    Permette di limitare l'accesso a richieste in localhost
    """

    def decorator(function):
        def onCall(request, *args, **kwargs):
            host = None
            remote_addr = None
            try:
                remote_addr = request.META.get('REMOTE_ADDR', None)
                host = request.META.get('HTTP_HOST', None)
                if not host or not remote_addr:
                    LOG.error("Parametri assenti")
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'description': 'Accesso negato'})
                elif remote_addr in host or remote_addr == "127.0.0.1":
                    return function(request, *args, **kwargs)
                LOG.error("Host della richiesta: {} non abilitato.".format(str(remote_addr)))
            except Exception as e:
                LOG.error('Indirizzo non abilitato: {} - Errore: {}'.format(str(remote_addr), e))
            return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'description': 'Accesso negato'})

        return onCall

    return decorator(function)


def auth_update_cert_api_required(function):
    """
    Permette di limitare l'accesso ad un utenza ADMIN
    """

    def decorator(function):
        def onCall(request, *args, **kwargs):
            authToken = None
            try:
                authToken = request.META.get('HTTP_AUTHORIZATION', None)
                username = request.META.get('HTTP_USERNAME', None)
                cert = request.POST.get('cert', None)
                if not authToken or not username or not cert:
                    LOG.error("Parametri assenti")
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                user = User.objects.filter(username=username.upper(), status=True, role=RoleTag.ADMIN.value).last()
                if not user:
                    LOG.error('Utente non trovato Username: {}'.format(str(username.upper())))
                    return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})
                if check_authtoken(username, cert, str(authToken)):
                    user.failureCounter = 0
                    user.save()
                    return function(request, *args, **kwargs)
                else:
                    user.failureCounter += 1
                    user.failureTimestamp = datetime.datetime.utcnow()
                    if user.failureCounter == 3:
                        user.status = False
                    user.save()
                    if not user.status:
                        LOG.error('Numero di tentativi massimo raggiunto. SO disabilitato Username: {}'.format(
                            str(username.upper())))
                        return JsonResponse(
                            {'statusCode': StatusCode.USER_DISABLED.value, 'message': 'Username disabilitata'})
            except Exception as e:
                LOG.error(
                    'Authorization Header non presente o non valido. AuthToken: {} - Errore: {}'.format(str(authToken),
                                                                                                        str(e)))
            return JsonResponse({'statusCode': StatusCode.UNAUTHORIZED.value, 'message': 'Accesso negato'})

        return onCall

    return decorator(function)

# -*- coding: utf-8 -*-
import base64
import datetime
import json
import logging

from OpenSSL import crypto
from django.http import JsonResponse
from django.views.decorators.http import require_POST

from api.decorators import auth_create_api_required, auth_activate_api_required, auth_sign_api_required, \
    auth_update_cert_api_required
from api.enumclass import StatusCode, RoleTag
from api.models import Entity, User
from api.utils import generate_pin

LOG = logging.getLogger(__name__)
ALG_SIGN = 'RS256'


# @localhost_required
def init(request):
    """
    Inizializza un nuovo ADMIN
    :params request: request
    :return: pin dell'admin, da cambiare successivamente da RAO
    """
    try:
        username = request.POST.get('username', None)
        entity = request.POST.get('entity', None)
        username = username.upper()
        if not username or not entity:
            LOG.error("Parametri assenti")
            return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value, 'message': 'Richiesta errata'})

        pin = generate_pin()

        entity_obj = Entity.objects.create(entity=entity.upper())
        User.objects.create(username=username, entity=entity_obj, pin=pin, secOfficer="SYSTEM",
                            creationTime=datetime.datetime.utcnow(), role=RoleTag.ADMIN.value)

        LOG.info("SO: {} Issuer: {} Operazione eseguita correttamente".format(username, entity))
        return JsonResponse({'statusCode': StatusCode.OK.value, 'message': pin})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)))
        return JsonResponse({'statusCode': StatusCode.ERROR.value, 'message': 'Errore'})


@require_POST
@auth_create_api_required
def create(request):
    """
    Crea un nuovo operatore disabilitato
    :param request: request
    :return: StatusCode
    """
    try:
        username = request.POST.get('username', None)
        entity = request.POST.get('entity', None)
        admin = request.META.get('HTTP_USERNAME', None)

        if not username or not entity or not admin:
            LOG.error("Parametri assenti")
            return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value, 'message': 'Richiesta errata'})

        username = username.upper()
        admin = admin.upper()

        pin = generate_pin()

        entity_obj = Entity.objects.filter(entity=entity.upper()).last()

        User.objects.create(username=username, secOfficer=admin, pin=pin, creationTime=datetime.datetime.utcnow(),
                            entity=entity_obj)
        LOG.info("SO: {} Operator: {} Issuer: {} Operazione eseguita correttamente".format(admin, username, entity))
        return JsonResponse({'statusCode': StatusCode.OK.value, 'message': pin})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)))
        return JsonResponse({'statusCode': StatusCode.ERROR.value, 'message': 'Errore'})


@require_POST
@auth_activate_api_required
def activate(request):
    """
    Attiva un operatore o un Security Officer disabilitato
    :param request: request
    :return: StatusCode
    """
    try:
        username = request.META.get('HTTP_USERNAME', None)
        entity = request.POST.get('entity', None)
        new_pin = request.POST.get('new_pin', None)
        cert = request.POST.get('cert', None)

        if not username or not entity or not new_pin:
            LOG.error("Parametri assenti")
            return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value, 'message': 'Richiesta errata'})

        username = username.upper()
        entity = entity.upper()

        entity_obj = Entity.objects.filter(entity=entity.upper()).last()
        if entity_obj:
            user = User.objects.filter(username=username, entity=entity_obj).last()
            if user:
                if user.role == RoleTag.ADMIN.value and not entity_obj.certData and not cert:
                    LOG.error(
                        "SO: {} Issuer: {} Certificato mancante".format(username, entity))
                    return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value,
                                         'message': 'Richiesta errata! Certificato mancante'})
                user.pin = new_pin
                user.status = True
                user.failureCounter = 0
                user.activationTime = datetime.datetime.utcnow()
                user.save()

                if user.role == RoleTag.ADMIN.value and cert:
                    entity_obj.certData = cert
                    entity_obj.status = True
                    entity_obj.save()
                    LOG.info("SO: {} Issuer: {} Operazione eseguita correttamente".format(username,
                                                                                           entity))
                    return JsonResponse({'statusCode': StatusCode.OK.value,
                                         'message': 'Operazione eseguita correttamente. Certificato caricato'})
                LOG.info("Operator: {} Issuer: {} Operazione eseguita correttamente".format(username,
                                                                                             entity))
                return JsonResponse({'statusCode': StatusCode.OK.value, 'message': 'Operazione eseguita correttamente'})
            else:
                LOG.error("FiscalNumber: {} Issuer: {} Codice Fiscale non trovato".format(username, entity))
        else:
            LOG.error("SO: {} Issuer: {} Issuer non trovato".format(username, entity))

        return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value, 'message': 'Richiesta errata'})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)))
        return JsonResponse({'statusCode': StatusCode.ERROR.value, 'message': 'Errore'})


@require_POST
@auth_sign_api_required
def sign(request):
    """
    Genera una firma tramite chiave privata
    :param request: request
    :return: StatusCode
    """
    try:
        username = request.META.get('HTTP_USERNAME', None)
        entity = request.POST.get('entity', None)
        payload = request.POST.get('payload', None)

        if not username or not entity or not payload:
            LOG.error("Parametri assenti")
            return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value, 'message': 'Richiesta errata'})

        entity_obj = Entity.objects.filter(entity=entity.upper(), status=True).last()
        user = User.objects.filter(username=username.upper(), status=True, entity=entity_obj).last()

        if entity_obj and user:
            priv_key = crypto.load_privatekey(crypto.FILETYPE_PEM, entity_obj.certData.encode())

            crt_obj = crypto.load_certificate(crypto.FILETYPE_PEM, entity_obj.certData.encode())

            cert_string = crypto.dump_certificate(crypto.FILETYPE_ASN1, crt_obj)

            headers = {'typ': 'JWT', 'alg': 'RS256', 'x5c': [base64.b64encode(cert_string).decode()]}
            b64_all = base64.urlsafe_b64encode(json.dumps(headers).encode()).decode().rstrip("=") + "." + \
                      base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
            signature = crypto.sign(priv_key, b64_all.encode(), "RSA-SHA256")
            sig = base64.urlsafe_b64encode(signature).decode().rstrip("=")

            LOG.info(
                "Operazione eseguita correttamente. Operator: {} Issuer: {} Signed: {}".format(username, entity, sig))
            return JsonResponse(
                {'statusCode': StatusCode.OK.value, 'cert': base64.b64encode(cert_string).decode(), "alg": ALG_SIGN,
                 "sign": sig})

        LOG.error("SO: {} Issuer: {} Informazioni non trovate".format(username, entity))
        return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value, 'message': 'Errore'})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)))
        return JsonResponse({'statusCode': StatusCode.ERROR.value, 'message': 'Errore'})


@require_POST
@auth_create_api_required
def reset_pin(request):
    """
    Genera un nuovo pin per operatore esistente
    :param request: request
    :return: StatusCode
    """
    try:
        username = request.POST.get('username', None)
        entity = request.POST.get('entity', None)
        admin = request.META.get('HTTP_USERNAME', None)

        if not username or not entity or not admin:
            LOG.error("Parametri assenti")
            return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value, 'message': 'Richiesta errata'})

        username = username.upper()
        admin = admin.upper()

        pin = generate_pin()

        entity_obj = Entity.objects.filter(entity=entity.upper()).last()

        user = User.objects.filter(username=username, secOfficer=admin, entity=entity_obj).last()
        if not user:
            LOG.error("SO: {} Operator: {} Issuer: {} Informazioni non trovate".format(admin, username, entity))
            return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value, 'message': 'Errore'})
        user.pin = pin
        user.lastUpdate = datetime.datetime.utcnow()
        user.save()
        LOG.info("SO: {} Operator: {} Issuer: {} Operazione eseguita correttamente".format(admin, username, entity))
        return JsonResponse({'statusCode': StatusCode.OK.value, 'message': pin})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)))
        return JsonResponse({'statusCode': StatusCode.ERROR.value, 'message': 'Errore'})


@require_POST
@auth_create_api_required
def deactivate(request):
    """
    Disabilita un operatore attivo
    :param request: request
    :return: StatusCode
    """
    try:
        username = request.POST.get('username', None)
        entity = request.POST.get('entity', None)
        admin = request.META.get('HTTP_USERNAME', None)

        if not username or not entity or not admin:
            LOG.error("Parametri assenti")
            return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value, 'message': 'Richiesta errata'})

        username = username.upper()
        admin = admin.upper()

        entity_obj = Entity.objects.filter(entity=entity.upper()).last()

        user = User.objects.filter(username=username, secOfficer=admin, entity=entity_obj).last()
        if not user:
            LOG.error("SO: {} Operator: {} Issuer: {} Informazioni non trovate".format(admin, username, entity))
            return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value, 'message': 'Errore'})
        user.status = False
        user.lastUpdate = datetime.datetime.utcnow()
        user.save()
        LOG.info("SO: {} Operator: {} Issuer: {} Operazione eseguita correttamente".format(admin, username, entity))
        return JsonResponse({'statusCode': StatusCode.OK.value, 'message': 'Operazione eseguita correttamente'})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)))
        return JsonResponse({'statusCode': StatusCode.ERROR.value, 'message': 'Errore'})


@require_POST
@auth_update_cert_api_required
def update_cert(request):
    """
    Aggiorna il certificato di un Entity object
    :param request: request
    :return: StatusCode
    """
    try:
        entity = request.POST.get('entity', None)
        admin = request.META.get('HTTP_USERNAME', None)
        cert = request.POST.get('cert', None)

        if not cert or not entity or not admin:
            LOG.error("Parametri assenti")
            return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value, 'message': 'Richiesta errata'})

        username = admin.upper()

        entity_obj = Entity.objects.filter(entity=entity.upper()).last()

        if entity_obj:
            entity_obj.certData = cert
            entity_obj.status = True
            entity_obj.save()
            LOG.info("SO: {} Issuer: {} Operazione eseguita correttamente".format(username,
                                                                                   entity))
            return JsonResponse({'statusCode': StatusCode.OK.value,
                                 'message': 'Operazione eseguita correttamente. Certificato caricato'})
        LOG.error("SO: {} Issuer: {} Issuer non trovato".format(username, entity))
        return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value, 'message': 'Richiesta errata'})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)))
        return JsonResponse({'statusCode': StatusCode.ERROR.value, 'message': 'Errore'})

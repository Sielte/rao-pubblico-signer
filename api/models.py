# -*- coding: utf-8 -*-
from django.db import models

from api.enumclass import RoleTag


class Entity(models.Model):
    entity = models.CharField(verbose_name='Entity', max_length=10, null=False, db_index=True)
    certData = models.TextField(verbose_name='Cert base64', null=True)
    status = models.BooleanField(verbose_name='Stato Entity', null=False, default=False)

    class Meta:
        verbose_name = 'Entity'
        verbose_name_plural = 'Entities'


class User(models.Model):
    username = models.CharField(verbose_name='Username', max_length=16, null=False, unique=True, db_index=True)
    pin = models.CharField(verbose_name='PIN', max_length=6, null=False)
    secOfficer = models.CharField(verbose_name='Security Officer', max_length=16, null=False)
    entity = models.ForeignKey(Entity, verbose_name='Entity', on_delete=None)
    creationTime = models.DateTimeField(verbose_name='Data creazione', null=False)
    activationTime = models.DateTimeField(verbose_name='Data attivazione', null=True)
    lastUpdate = models.DateTimeField(verbose_name='Data ultimo aggiornamento', null=True)
    status = models.BooleanField(verbose_name='Stato User', null=False, default=False)
    role = models.CharField(verbose_name='Nome', choices=[(tag, tag.value) for tag in RoleTag], max_length=15,
                            null=False, default=RoleTag.OPERATOR.value)
    failureTimestamp = models.DateTimeField(verbose_name='Data tentativo errato', null=True)
    failureCounter = models.SmallIntegerField(verbose_name='Contatore tentativi errati', default=0)

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

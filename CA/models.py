from django.db import models


# Create your models here.
class User(models.Model):
    name = models.CharField(max_length=50, null=True, blank=True)
    national_code = models.CharField(max_length=12, null=True, blank=True, unique=True)


class Certificaat(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    private_key = models.CharField(max_length=100, unique=True)
    public_key = models.CharField(max_length=100, unique=True)
    life_time = models.CharField(max_length=100,default=None)
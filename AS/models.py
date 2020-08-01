from django.db import models


class RestrictedNationalCodes(models.Model):  # national codes that aren't allowed to vote
    national_code = models.CharField(max_length=12, null=True, blank=True, unique=True)


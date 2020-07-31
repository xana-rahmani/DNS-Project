from django.db import models


# Create your models here.
class Candidates(models.Model):
    candidate_id = models.CharField(max_length=100, unique=True)
    number_of_votes = models.IntegerField(default=0)


class Votes(models.Model):
    public_key = models.CharField(max_length=100, unique=True)
    voted_to = models.ForeignKey(Candidates, on_delete=models.CASCADE)
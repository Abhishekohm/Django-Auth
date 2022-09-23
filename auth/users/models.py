from django.db import models
import jwt
from datetime import datetime, timedelta

# Create your models here.


class User(models.Model):
    username = models.CharField(max_length=50, unique=True)
    email = models.CharField(max_length=150, unique=True, blank=True)
    password = models.CharField(max_length=255)
    refreshToken = models.CharField(max_length=255)
    createdOn = models.TimeField(auto_now_add=True)

    def getAccessToken(self):
        payload = {
            'id': self.id,
            'exp': datetime.utcnow() + timedelta(minutes=10)
        }
        jwt_token = jwt.encode(payload, 'secret', algorithm="HS256")
        return jwt_token

    def getRefreshToken(self):
        payload = {
            'id': self.id,
            'exp': datetime.utcnow() + timedelta(days=1)
        }
        jwt_token = jwt.encode(payload, 'secret', algorithm="HS256")
        self.refreshToken = jwt_token
        self.save()
        return jwt_token

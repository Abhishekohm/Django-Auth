
from django.urls import path
from .views import login, register, private, refresh
urlpatterns = [
    path('login/', login),
    path('register/', register),
    path('private/', private),
    path('refresh/', refresh)
]

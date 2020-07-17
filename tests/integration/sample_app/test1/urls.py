from django.urls import path

from .views.home import *


urlpatterns = [
    path('', HomeView.as_view(), name="home"),
    path('basic', BasicContextView.as_view(), name="basic-context"),
]
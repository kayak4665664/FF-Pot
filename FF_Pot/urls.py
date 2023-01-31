"""FF_Pot URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from . import views
from django.conf.urls import handler400, handler403, handler404, handler500
from django.contrib.staticfiles.views import serve
from django.urls import re_path


def return_statics(request, path, insecure=True, **kwargs):
    return serve(request, path, insecure, **kwargs)


urlpatterns = [
    path("login/", views.login),
    path("home/", views.home),
    path("", views.home),
    re_path(r"^statics/(?P<path>.*)$", return_statics, name="statics"),
]

handler400 = views.error
handler403 = views.error
handler404 = views.error
handler500 = views.error_500

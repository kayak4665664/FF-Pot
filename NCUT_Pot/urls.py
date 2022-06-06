"""NCUT_Pot URL Configuration

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

urlpatterns = [
    path("login/", views.login),
    path("home/", views.home),
    path("/", views.home),
    path("", views.home),
]

handler400 = views.error
handler403 = views.error
handler404 = views.error
handler500 = views.error_500
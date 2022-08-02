from django.urls import path

from .views import (
    callback,
    dashboard,
    dashboard_msg,
    index,
    subscribe,
    twitter,
    user_logout,
)

app_name = "follow_me"
urlpatterns = [
    path("", index, name="index"),
    path("callback", callback, name="callback"),
    path("dashboard", dashboard, name="dashboard"),
    path("subscribe", subscribe, name="subscribe"),
    path("twitter", twitter, name="twitter"),
    path("logout/", user_logout, name="logout"),
    path("dashboard/msg", dashboard_msg, name="dashboard_msg"),
]

from django.urls import path

from .views import (
    callback,
    dashboard,
    inspiration,
    auto_dm,
    dashboard_msg,
    index,
    subscribe,
    create_tweet,
    twitter,
    user_logout,
    delete_tweet,
)

app_name = "follow_me"
urlpatterns = [
    path("", index, name="index"),
    path("callback", callback, name="callback"),
    path("dashboard", dashboard, name="dashboard"),
    path("auto_dm", auto_dm, name="auto_dm"),
    path("inspiration", inspiration, name="inspiration"),
    path("subscribe", subscribe, name="subscribe"),
    path("create_tweet", create_tweet, name="create_tweet"),
    path("delete_tweet", delete_tweet, name="delete_tweet"),
    path("twitter", twitter, name="twitter"),
    path("logout/", user_logout, name="logout"),
    path("dashboard/msg", dashboard_msg, name="dashboard_msg"),
]

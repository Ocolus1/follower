import base64
import hashlib
import hmac
import json

import tweepy
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from requests_oauthlib import OAuth1

from .api import createSubscription, deleteSubscription, getMySubscription
from .config import create_api
from .models import Message, User

oauth_store = {}


# Create your views here.
def index(request):
    # # calling the instance of the consumer
    user_auth = create_api()

    # Making a get request to obtain the athourized url
    authorize_url = user_auth.get_authorization_url(signin_with_twitter=True)

    request_token = user_auth.request_token["oauth_token"]
    request_secret = user_auth.request_token["oauth_token_secret"]

    oauth_store[request_token] = request_secret
    content = {"authorize_url": authorize_url}
    return render(request, "follow_me/index.html", content)


def callback(request):
    verifier = request.GET.get("oauth_verifier")
    oauth_token = request.GET.get("oauth_token")
    if not verifier:
        error_message = "callback param(s) missing"
        content = {"error_message": error_message}
        return render(request, "follow_me/error.html", content)
    if oauth_token not in oauth_store:
        error_message = "oauth_token not found locally"
        content = {"error_message": error_message}
        return render(request, "follow_me/error.html", content)
    request_secret = oauth_store[oauth_token]
    user_auth = create_api()
    user_auth.request_token = {
        "oauth_token": oauth_token,
        "oauth_token_secret": request_secret,
    }
    access_token, access_token_secret = user_auth.get_access_token(verifier)
    user_auth.set_access_token(access_token, access_token_secret)
    api = tweepy.API(user_auth, wait_on_rate_limit=True)
    id = api.verify_credentials().id_str
    user = api.get_user(user_id=id)
    name = user.name
    screen_name = user.screen_name
    follower_len = user.followers_count
    del oauth_store[oauth_token]
    if User.objects.filter(twitter_id=int(id)).exists():
        prev_user = User.objects.get(twitter_id=int(id))
        ac = prev_user.access_token == access_token
        ac_secret = prev_user.access_token_secret == access_token_secret
        if ac is True and ac_secret is True:
            pass
        else:
            prev_user.access_token = access_token
            prev_user.access_token_secret = access_token_secret
            prev_user.save()

        user = authenticate(twitter_id=int(id), password=access_token)
        if user is not None:
            login(request, user)
            return redirect("dashboard")
        else:
            print("An error occured inner")
    else:
        created = User.objects.create_user(
            twitter_id=int(id), name=name, password=access_token
        )
        if created:
            created.save()
            created.screen_name = screen_name
            created.num_of_followers = follower_len
            created.access_token = access_token
            created.access_token_secret = access_token_secret
            created.save()

            user = authenticate(twitter_id=int(id), password=access_token)
            if user is not None:
                login(request, user)
                return redirect("dashboard")
            else:
                print("An error occured")
    return redirect("dashboard")


def dashboard(request):
    msg = Message.objects.filter(user=request.user)
    content = {"messages": msg, "msg": msg.last()}
    return render(request, "follow_me/dashboard/dashboard.html", content)


@csrf_exempt
def subscribe(request):
    msg = Message.objects.all()
    user = User.objects.get(twitter_id=request.user.twitter_id)
    client_key = settings.TWITTER_CONSUMER_KEY
    client_secret = settings.TWITTER_CONSUMER_SECRET
    resource_owner_key = user.access_token
    resource_owner_secret = user.access_token_secret
    oauth = OAuth1(
        client_key,
        client_secret=client_secret,
        resource_owner_key=resource_owner_key,
        resource_owner_secret=resource_owner_secret,
    )
    response = getMySubscription(oauth)
    if response.status_code == 204:
        check_sub = "verified"
    else:
        check_sub = "not_verified"
    if request.method == "POST":
        msg = json.loads(request.body)["msg"]
        if msg == "free subscription":
            res = createSubscription(oauth)
            if res.status_code == 204:
                return JsonResponse({"message": "Success"})
            else:
                return JsonResponse({"message": "Failure"})
        if msg == "cancel subscription":
            res = deleteSubscription(user.twitter_id)
            if res.status_code == 204:
                return JsonResponse({"message": "Success"})
            else:
                return JsonResponse({"message": "Failure"})
    content = {"messages": msg, "msg": msg.last(), "check_sub": check_sub}
    return render(request, "follow_me/dashboard/subscription.html", content)


@csrf_exempt
def dashboard_msg(request):
    msg = json.loads(request.body)["msg"]
    Message.objects.create(user=request.user, message=msg)
    return JsonResponse({"message": "Success"})


@csrf_exempt
def twitter(request):
    if request.method == "GET":
        # creates HMAC SHA-256 hash from incomming token and your consumer secret
        text = request.GET.get("crc_token").encode("utf-8")

        key = bytes(settings.TWITTER_CONSUMER_SECRET, "utf-8")
        sha256_hash_digest = hmac.new(key, msg=text, digestmod=hashlib.sha256).digest()

        # construct response data with base64 encoded hash
        response = {
            "response_token": "sha256="
            + base64.b64encode(sha256_hash_digest).decode("utf-8")
        }
        # returns properly formatted json response
        return JsonResponse(response)

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            # print("data ------" , data)
            if data["follow_events"]:
                broad = data["follow_events"]
                # for i in broad:e
                user_id = data["for_user_id"]
                target_id = broad[0]["target"]["id"]
                if broad[0]["type"] == "follow" and target_id == user_id:
                    if User.objects.filter(twitter_id=target_id).exists():
                        user = User.objects.get(twitter_id=target_id)
                        target = Message.objects.filter(user=user).last()
                        user_auth = create_api()
                        user_auth.set_access_token(
                            user.access_token, user.access_token_secret
                        )
                    source_id = broad[0]["source"]["id"]
                    api = tweepy.API(user_auth)
                    api.send_direct_message(source_id, target.message)
        except Exception:
            print("Done")

        return JsonResponse(data, status=200)


# Logout
def user_logout(request):
    logout(request)
    return HttpResponseRedirect("/")

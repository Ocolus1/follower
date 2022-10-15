import base64
import hashlib
import hmac
import json
import logging
from .enums import TimeInterval, SetupStatus

import tweepy
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q
from requests_oauthlib import OAuth1
from .utils import parse_tweets

from .api import createSubscription, deleteSubscription, getMySubscription
from .config import create_api
from .models import Message, User, Tweets, OuathStore, AutoTweets

logger = logging.getLogger(__name__)


# Create your views here.
def index(request):
    if request.user.is_authenticated:
        return redirect("follow_me:dashboard")
    # # calling the instance of the consumer
    user_auth = create_api()

    # Making a get request to obtain the authorized url
    authorize_url = user_auth.get_authorization_url(signin_with_twitter=True)

    request_token = user_auth.request_token["oauth_token"]
    request_secret = user_auth.request_token["oauth_token_secret"]

    OuathStore.objects.create(
        request_token=request_token, request_secret=request_secret
    )
    content = {"authorize_url": authorize_url}
    return render(request, "follow_me/index.html", content)


def callback(request):
    verifier = request.GET.get("oauth_verifier")
    oauth_token = request.GET.get("oauth_token")
    if not verifier:
        error_message = "callback param(s) missing"
        content = {"error_message": error_message}
        return render(request, "follow_me/error.html", content)
    if not OuathStore.objects.filter(request_token=oauth_token).exists():
        error_message = f"oauth_token not found locally"
        content = {"error_message": error_message}
        return render(request, "follow_me/error.html", content)
    oauth_store = OuathStore.objects.get(request_token=oauth_token)
    request_secret = oauth_store.request_secret
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
    oauth_store.delete()
    if User.objects.filter(twitter_id=int(id)).exists():
        prev_user = User.objects.get(twitter_id=int(id))
        ac = prev_user.access_token == access_token
        ac_secret = prev_user.access_token_secret == access_token_secret
        if not ac and not ac_secret:
            prev_user.access_token = access_token
            prev_user.access_token_secret = access_token_secret
            prev_user.set_password(access_token)
            prev_user.save()

        user = authenticate(twitter_id=id, password=access_token)
        if user is not None:
            login(request, user)
            return redirect("follow_me:dashboard")
        else:
            print("An error occurred inner")
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
                return redirect("follow_me:dashboard")
            else:
                print("An error occurred")
    return redirect("follow_me:dashboard")


@login_required(login_url='/')
def dashboard(request):
    query, reply_count, retweet_counts, likes_count = "", "", "", ""

    # fetching all tweets objects from database pertaining to the request user
    tweets = Tweets.objects.filter(user=request.user)
    if request.method == "POST":
        query = request.POST["q"]
        reply_count = request.POST["reply_count"]
        retweet_counts = request.POST["retweet_counts"]
        likes_count = request.POST["likes_count"]
        if query and reply_count and retweet_counts and likes_count:
            tweets = Tweets.objects.filter(user=request.user).filter(
                Q(full_text__icontains=query) and Q(reply_count__gte=int(reply_count))
                and Q(retweet_counts__gte=int(retweet_counts)) and Q(likes_count__gte=int(likes_count))
            )
        elif query and reply_count and retweet_counts:
            tweets = Tweets.objects.filter(user=request.user).filter(
                Q(full_text__icontains=query) and Q(reply_count__gte=int(reply_count))
                and Q(retweet_counts__gte=int(retweet_counts))
            )
        elif query and reply_count and likes_count:
            tweets = Tweets.objects.filter(user=request.user).filter(
                Q(full_text__icontains=query) and Q(reply_count__gte=int(reply_count))
                and Q(likes_count__gte=int(likes_count))
            )
        elif query and retweet_counts and likes_count:
            tweets = Tweets.objects.filter(user=request.user).filter(
                Q(full_text__icontains=query) and Q(retweet_counts__gte=int(retweet_counts))
                and Q(likes_count__gte=int(likes_count))
            )
        elif query and reply_count:
            tweets = Tweets.objects.filter(user=request.user).filter(
                Q(full_text__icontains=query) and Q(reply_count__gte=int(reply_count))
            )
        elif query and retweet_counts:
            tweets = Tweets.objects.filter(user=request.user).filter(
                Q(full_text__icontains=query) and Q(retweet_counts__gte=int(retweet_counts))
            )
        elif query and likes_count:
            tweets = Tweets.objects.filter(user=request.user).filter(
                Q(full_text__icontains=query) and Q(likes_count__gte=int(likes_count))
            )
        elif query:
            tweets = Tweets.objects.filter(user=request.user).filter(
                Q(full_text__icontains=query) | Q(full_text__icontains=query)
            )
        else:
            tweets = Tweets.objects.filter(user=request.user).filter(
                Q(full_text__icontains=query) or Q(reply_count__gte=int(reply_count))
                or Q(retweet_counts__gte=int(retweet_counts)) or Q(likes_count__gte=int(likes_count))
            )
    p = Paginator(tweets, 6) # creating a paginator object
    # getting the desired page number from url
    page_number = request.GET.get('page')
    try:
        tweet_obj = p.get_page(page_number)  # returns the desired page object
    except PageNotAnInteger:
        # if page_number is not an integer then assign the first page
        tweet_obj = p.page(1)
    except EmptyPage:
        # if page is empty then return last page
        tweet_obj = p.page(p.num_pages)

    content = {
        "tweets": tweet_obj,
        "query": query,
        "likes_count": likes_count,
        "retweet_counts": retweet_counts,
        "reply_count" : reply_count
    }
    return render(request, "follow_me/dashboard/dashboard.html", content)


@login_required(login_url='/')
def inspiration(request):
    query = ""
    tweets = Tweets.objects.filter(user=request.user)
    p = Paginator(tweets, 6) # creating a paginator object
    # getting the desired page number from url
    page_number = request.GET.get('page')
    try:
        tweet_obj = p.get_page(page_number)  # returns the desired page object
    except PageNotAnInteger:
        # if page_number is not an integer then assign the first page
        tweet_obj = p.page(1)
    except EmptyPage:
        # if page is empty then return last page
        tweet_obj = p.page(p.num_pages)
    if request.method == "POST":
        user = User.objects.get(twitter_id=request.user.twitter_id)
        user_auth = create_api()
        user_auth.set_access_token(
            user.access_token, user.access_token_secret
        )
        api = tweepy.API(user_auth, wait_on_rate_limit=True) # wait on rate limit to avoid rate limit error
        try:
            api.verify_credentials()
        except:
            logout(request)
            return HttpResponseRedirect("/")
        query = request.POST["search"]
        _from = request.POST["from"]
        _to = request.POST["to"]
        if not query:
            return redirect("follow_me:inspiration")
        elif query and _from and _to:
            _from = _from.split("-")
            _from = "".join(_from)
            _from = _from + "0000"
            _to = _to.split("-")
            _to = "".join(_to)
            _to = _to + "0000"
            search_object = api.search_full_archive(label='dev', query=str(query), fromDate=_from, toDate=_to)
        elif query and _from :
            _from = _from.split("-")
            _from = "".join(_from)
            _from = _from + "0000"
            search_object = api.search_full_archive(label='dev', query=str(query), fromDate=_from)
        elif query and _to :
            _to = _to.split("-")
            _to = "".join(_to)
            _to = _to + "0000"
            search_object = api.search_full_archive(label='dev', query=str(query), toDate=_to)
        else:
            search_object = api.search_full_archive(label='dev', query=str(query))
        parsed_search = parse_tweets(search_object)
        logger.info("got here")
        for search in parsed_search:
                logger.info("start")
                Tweets.objects.create(
                    user=request.user,
                    profile_image=search['profile_image'],
                    full_text=search['full_text'],
                    likes_count=search['likes_count'],
                    retweet_counts=search['retweet_counts'],
                    reply_count=search['reply_count'],
                    date=search['date'],
                )
                logger.info("end")
        tweets = Tweets.objects.filter(user=request.user)
    content = {
        "tweets": tweet_obj,
        "query": query,
        }
    return render(request, "follow_me/dashboard/daily_inspiration.html", content)


@login_required(login_url='/')
def create_tweet(request):
    user = User.objects.get(twitter_id=request.user.twitter_id)
    user_auth = create_api()
    user_auth.set_access_token(
        user.access_token, user.access_token_secret
    )
    api = tweepy.API(user_auth, wait_on_rate_limit=True) # wait on rate limit to avoid rate limit error
    if request.method == "POST":
        id = request.POST["id"]
        tweet = request.POST["tweet_body"]
        try:
            api.verify_credentials()
        except:
            logout(request)
            return HttpResponseRedirect("/")
        api.update_status(tweet)
        tweet_obj = Tweets.objects.get(pk=id)
        tweet_obj.delete()
        return redirect("follow_me:dashboard")


@login_required(login_url='/')
def delete_tweet(request):
    if request.method == "POST":
        id = request.POST["delete_id"]
        tweet_obj = Tweets.objects.get(pk=id)
        tweet_obj.delete()
        return redirect("follow_me:dashboard")


@login_required(login_url='/')
def auto_dm(request):
    msg = Message.objects.filter(user=request.user)
    content = {"messages": msg, "msg": msg.last()}
    return render(request, "follow_me/dashboard/auto_dm.html", content)


@login_required(login_url='/')
def auto_tweet(request):
    tweets = AutoTweets.objects.filter(user=request.user)
    user = User.objects.get(twitter_id=request.user.twitter_id)
    if user.status == SetupStatus.active:
        status = "On"
    else:
        status = "Off"
    p = Paginator(tweets, 6) # creating a paginator object
    # getting the desired page number from url
    page_number = request.GET.get('page')
    try:
        tweet_obj = p.get_page(page_number)  # returns the desired page object
    except PageNotAnInteger:
        # if page_number is not an integer then assign the first page
        tweet_obj = p.page(1)
    except EmptyPage:
        # if page is empty then return last page
        tweet_obj = p.page(p.num_pages)
    if request.method == "POST":
        tweet_body = request.POST["tweet_body"]
        AutoTweets.objects.create(user=request.user, full_text=tweet_body)
        return redirect("follow_me:auto_tweet")
    content = {
        "tweets": tweet_obj,
        "status": status,
    }
    return render(request, "follow_me/dashboard/auto_tweet.html", content)


@login_required(login_url='/')
def auto_tweet_status(request):
    user = User.objects.get(twitter_id=request.user.twitter_id)

    if request.method == "POST":
        select = request.POST["select_box"]
        check_box = request.POST.getlist('check_box')
        # checking the value of select box to get the time interval
        if select == "1":
            user.time_interval = TimeInterval.three_hours
        elif select == "2":
            user.time_interval = TimeInterval.six_hours
        else:
            user.time_interval = TimeInterval.twelve_hours
        user.setup_task()

        # checking the value of check box to get the status of auto tweet
        if 'on' in check_box:
            user.status = SetupStatus.active
            user.save()
        else:
            user.status = SetupStatus.disabled
            user.save()
        return redirect("follow_me:auto_tweet")


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

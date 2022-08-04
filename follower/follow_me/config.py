import tweepy
from django.conf import settings


def create_api():
    """
    This function initialise an instance of the user
    and returns the instance.
    """
    auth = tweepy.OAuth1UserHandler(
        settings.TWITTER_CONSUMER_KEY,
        settings.TWITTER_CONSUMER_SECRET,
        callback=f"{settings.CALLBACK_URL}",
    )
    return auth

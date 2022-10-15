import logging

import tweepy
from celery import shared_task
from .enums import TimeInterval, SetupStatus

from .models import User, AutoTweets
from .config import create_api

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


@shared_task(name="computation_heavy_task")
def computation_heavy_task(setup_id):
    user = User.objects.get(id=setup_id)
    logger.info(f"Starting user {user.screen_name}")
    if user.is_admin == True:
        pass
    else:
        user_auth = create_api()
        user_auth.set_access_token(
            user.access_token, user.access_token_secret
        )
        logger.info(f"Calling user {user.screen_name} api")
        try:
            api = tweepy.API(user_auth, wait_on_rate_limit=True) # wait on rate limit to avoid rate limit error
            logger.info(f"Starting user {user.screen_name} api")
            try:
                api.verify_credentials()
                if AutoTweets.objects.filter(user=user).order_by('id')[0]:
                    tweets = AutoTweets.objects.filter(user=user).order_by('id')[0]
                    api.update_status(tweets.full_text)
                    logger.info(f"Tweet created by {user.screen_name}")
                    tweets.delete()
                    logger.info(f"Tweet delete by {user.screen_name}")
                    logger.info(f"Credentials user {user.screen_name}")
            except Exception as e:
                user.status = SetupStatus.disabled
                user.save()
                logger.error("Error creating API", exc_info=True)
        except tweepy.errors.TooManyRequests:
            print("rate limit reached")

        logger.info(f"Ending user {user.screen_name}")

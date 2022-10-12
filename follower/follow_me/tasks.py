# import logging

# import tweepy
# from celery import shared_task
# from django.conf import settings

# from .enums import SetupStatus
# from .models import User

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger()


# @shared_task(name="computation_heavy_task")
# def computation_heavy_task(setup_id):
#     user = User.objects.get(id=setup_id)
#     logger.info(f"Starting user {user.screen_name}")
#     if user.is_admin is True:
#         pass
#     else:
#         auth = tweepy.OAuth1UserHandler(
#             settings.TWITTER_CONSUMER_KEY,
#             settings.TWITTER_CONSUMER_SECRET,
#             user.access_token,
#             user.access_token_secret,
#         )
#         logger.info(f"Calling user {user.screen_name} api")
#         try:
#             api = tweepy.API(auth)
#             logger.info(f"Starting user {user.screen_name} api")
#             try:
#                 api.verify_credentials()
#                 id = api.verify_credentials().id_str
#                 followers = api.get_follower_ids(user_id=id)
#                 logger.info(f"User follower created {len(followers)}")
#                 d = []
#                 for i in user.user_follower.all():
#                     d.append(i.follower)
#                 for follower in followers:
#                     if follower in d:
#                         pass
#                     else:
#                         msg = "Hello! Thanks for folowing me."
#                         api.send_direct_message(follower, msg)
#                         logger.info(f"Sent message to {follower}")
#                         User_list.objects.create(user=user, follower=follower)
#                         logger.info("User follower created")
#                 logger.info(f"Credentials user {user.screen_name}")
#             except Exception as e:
#                 user.status = SetupStatus.disabled
#                 user.save()
#                 logger.error(f"Error creating API {e}", exc_info=True)
#         except tweepy.errors.TooManyRequests:
#             print("rate limit reached")

#     logger.info(f"Ending user {user.screen_name}")


# @shared_task(name="check_20_min")
# def check_20_min(setup_id):
#     user = User.objects.get(id=setup_id)
#     if user.status == SetupStatus.active:
#         pass
#     else:
#         user.status = SetupStatus.active
#         user.save()

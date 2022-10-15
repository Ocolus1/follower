from django.apps import AppConfig


class FollowMeConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "follower.follow_me"

    def ready(self):
        import follower.follow_me.signals


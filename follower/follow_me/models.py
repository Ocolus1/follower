import json
from unicodedata import name
from django.contrib.auth.models import AbstractUser, BaseUserManager
from .enums import TimeInterval, SetupStatus
from django_enum_choices.fields import EnumChoiceField
from django.db import models
from django.utils import timezone
from django_celery_beat.models import IntervalSchedule, PeriodicTask
import string


class MyUserManager(BaseUserManager):
    def create_user(self, twitter_id, name, password=None):

        user = self.model(twitter_id=twitter_id, name=name)

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, twitter_id, name, password=None):
        """
        Creates and saves a superuser id and password.
        """
        user = self.create_user(
            twitter_id,
            name,
            password,
        )
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractUser):
    username = None
    twitter_id = models.BigIntegerField(unique=True)
    name = models.CharField(max_length=500, blank=True, null=True)
    screen_name = models.CharField(max_length=500, blank=True, null=True)
    status = EnumChoiceField(SetupStatus, default=SetupStatus.disabled)
    time_interval = EnumChoiceField(TimeInterval, default=TimeInterval.three_hours)
    num_of_followers = models.IntegerField(blank=True, null=True)
    access_token = models.CharField(max_length=500, blank=True, null=True)
    access_token_secret = models.CharField(max_length=500, blank=True, null=True)
    created_at = models.DateTimeField(
        "timestamp", auto_now_add=True, editable=False, db_index=True
    )
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    task = models.OneToOneField(
        PeriodicTask,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )

    objects = MyUserManager()

    USERNAME_FIELD = "twitter_id"
    REQUIRED_FIELDS = ["name"]

    def __str__(self):
        return f"{self.twitter_id}"

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    def delete(self, *args, **kwargs):
        if self.task is not None:
            self.task.delete()
        return super(User, self).delete(*args, **kwargs)

    def setup_task(self):
        if PeriodicTask.objects.filter(name=self.twitter_id).exists():
            periodic_obj = PeriodicTask.objects.get(name=self.twitter_id)
            periodic_obj.interval = self.interval_schedule
            periodic_obj.save()
        else:
            self.task = PeriodicTask.objects.create(
                name=self.twitter_id,
                task='computation_heavy_task',
                interval=self.interval_schedule,
                args=json.dumps([self.id]),
                start_time=timezone.now(),
                enabled=False
            )
            self.save()

    @property
    def interval_schedule(self):
        if self.time_interval == TimeInterval.three_hours:
            return IntervalSchedule.objects.get_or_create(
                every=3,
                period=IntervalSchedule.HOURS
            )[0]
        elif self.time_interval == TimeInterval.six_hours:
            return IntervalSchedule.objects.get_or_create(
                every=6,
                period=IntervalSchedule.HOURS
            )[0]
        elif self.time_interval == TimeInterval.twelve_hours:
            return IntervalSchedule.objects.get_or_create(
                every=12,
                period=IntervalSchedule.HOURS
            )[0]


class Message(models.Model):
    user = models.ForeignKey(User, verbose_name="user", on_delete=models.CASCADE)
    message = models.TextField()
    query = models.CharField(max_length=255, blank=True, null=True, default="crypto")
    created_At = models.DateTimeField(
        "timestamp", auto_now_add=True, editable=False, db_index=True
    )

    def __str__(self):
        return self.user.name + self.message[0:20]


class Tweets(models.Model):
    user = models.ForeignKey(User, verbose_name="user", on_delete=models.CASCADE, blank=True, null=True)
    profile_image = models.CharField(max_length=500, blank=True, null=True)
    full_text = models.TextField()
    likes_count = models.IntegerField(blank=True, null=True)
    retweet_counts = models.IntegerField(blank=True, null=True)
    reply_count = models.IntegerField(blank=True, null=True)
    date = models.CharField(max_length=255, blank=True, null=True)


class OuathStore(models.Model):
    request_token = models.CharField(max_length=255, blank=True, null=True)
    request_secret = models.CharField(max_length=255, blank=True, null=True)


class AutoTweets(models.Model):
    user = models.ForeignKey(User, verbose_name="user", on_delete=models.CASCADE, blank=True, null=True)
    full_text = models.TextField()
    created_At = models.DateTimeField(auto_now_add=True, editable=False, db_index=True)

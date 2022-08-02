from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models


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
    num_of_followers = models.IntegerField(blank=True, null=True)
    access_token = models.CharField(max_length=500, blank=True, null=True)
    access_token_secret = models.CharField(max_length=500, blank=True, null=True)
    created_at = models.DateTimeField(
        "timestamp", auto_now_add=True, editable=False, db_index=True
    )
    is_active = models.BooleanField(default=True)

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


class Message(models.Model):
    user = models.ForeignKey(User, verbose_name="user", on_delete=models.CASCADE)
    message = models.TextField()
    created_At = models.DateTimeField(
        "timestamp", auto_now_add=True, editable=False, db_index=True
    )

    def __str__(self):
        return self.user.name + self.message[0:20]

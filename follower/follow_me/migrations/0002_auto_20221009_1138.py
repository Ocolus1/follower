# Generated by Django 3.2.14 on 2022-10-09 11:38

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('follow_me', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='message',
            name='query',
            field=models.CharField(blank=True, default='crypto', max_length=255, null=True),
        ),
        migrations.CreateModel(
            name='Tweets',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('profile_image', models.CharField(blank=True, max_length=500, null=True)),
                ('full_text', models.TextField()),
                ('likes_count', models.IntegerField(blank=True, null=True)),
                ('retweet_counts', models.IntegerField(blank=True, null=True)),
                ('reply_count', models.IntegerField(blank=True, null=True)),
                ('date', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='user')),
            ],
        ),
    ]

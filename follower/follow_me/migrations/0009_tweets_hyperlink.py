# Generated by Django 3.2.14 on 2022-10-28 17:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('follow_me', '0008_auto_20221015_1822'),
    ]

    operations = [
        migrations.AddField(
            model_name='tweets',
            name='hyperlink',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
    ]
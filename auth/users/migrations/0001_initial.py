# Generated by Django 4.1.1 on 2022-09-21 06:34

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=50, unique=True)),
                ('email', models.CharField(blank=True, max_length=150, unique=True)),
                ('password', models.CharField(max_length=255)),
                ('refreshToken', models.CharField(max_length=255)),
                ('createdOn', models.TimeField(auto_now_add=True)),
            ],
        ),
    ]

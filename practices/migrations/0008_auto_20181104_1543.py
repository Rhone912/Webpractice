# Generated by Django 2.1.2 on 2018-11-04 15:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('practices', '0007_auto_20181104_1155'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='password',
            field=models.CharField(max_length=256),
        ),
    ]

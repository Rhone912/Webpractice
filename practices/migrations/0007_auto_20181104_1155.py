# Generated by Django 2.1.2 on 2018-11-04 11:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('practices', '0006_auto_20181104_1154'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='id',
            field=models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]

from rest_framework import serializers

from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.conf import settings

from users.models import ToDoUser

def validate_username_unique(username):

    if ToDoUser.objects.filter(username=username).exists():

        raise serializers.ValidationError("Користувач із таким іменем вже існує.")

    return username


def validate_email_unique(email):

    if ToDoUser.objects.filter(email=email).exists():

        raise serializers.ValidationError("Користувач із цією електронною адресою вже існує.")

    return email


def validate_password_strength(password):

    if len(password) < 8:

        raise serializers.ValidationError("Пароль має бути не менше 8 символів.")

    elif not any(char.isdigit() for char in password):

        raise serializers.ValidationError("Пароль має містити хоча б одну цифру.")

    elif not any(not char.isalnum() for char in password):

        raise serializers.ValidationError("Пароль повинен містити хоча б один спеціальний символ.")

    return password


def validate_passwords_match(password, confirm_password):

    if password != confirm_password:

        raise serializers.ValidationError({"confirm_password":"Паролі мають збігатися."})


def create_user(username, email, password):

    user = ToDoUser(username=username, email=email)

    user.set_password(password)

    user.save()

    return user


def authenticate_user(username, password):

    user = authenticate(username=username, password=password)

    if user is None:
    
        try:
        
            user = ToDoUser.objects.get(username=username)
        
        except ToDoUser.DoesNotExist:
        
            raise serializers.ValidationError({"username": "Користувач не існує."})
    
        raise serializers.ValidationError({"password": "Неправильний пароль."})

    return user


def send_password_reset_email(user):

    uid = urlsafe_base64_encode(str(user.pk).encode())

    token = default_token_generator.make_token(user)

    reset_url = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})

    full_url = f'{settings.FRONTEND_URL}{reset_url}'

    send_mail(
        'Password Reset Request',
        f'Click the link to reset your password: {full_url}',
        'todo@gmail.com',
        [user.email]
    )


def validate_reset_password_token(uidb64, token):

    try:
        uid = urlsafe_base64_decode(uidb64).decode('utf-8')
    
        user = ToDoUser.objects.get(pk=uid)
    
    except (ValueError, TypeError, ToDoUser.DoesNotExist):
    
        raise ValueError('Неправильний користувач.')

    if not default_token_generator.check_token(user, token):

        raise ValueError("Неправильний чи прострочений токен.")

    return user


def reset_user_password(user, new_password):

    user.set_password(new_password)

    user.save()

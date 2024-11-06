from rest_framework import serializers, status
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
import base64

from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode

from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

from django.urls import reverse
from django.conf import settings
from django.core.mail import send_mail

from todo_user.models import ToDoUser


class RegistrationSerializer(serializers.ModelSerializer):

    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    """Serializer for user's registration"""

    class Meta:

        """Initialization fields and models"""

        model = ToDoUser

        fields = [
                'username',
                'email',
                'password',
                'confirm_password',
                ]

    def validate_username(self, value):

        """chekcs username on unique in db"""

        if ToDoUser.objects.filter(username=value).exists():

            raise serializers.ValidationError({"username": "Користувач із таким іменем вже існує."})

        return value

    def validate_email(self, value):

        """checks email on unique in db"""

        if ToDoUser.objects.filter(email=value).exists():

            raise serializers.ValidationError("Користувач із цією електронною адресою вже існує.")

        return value

    def validate_password(self, value):

        """Validates the password strength"""

        if len(value) < 8:

            raise serializers.ValidationError("Пароль має бути не менше 8 символів.")

        has_digit = any(char.isdigit() for char in value)

        if not has_digit:

            raise serializers.ValidationError("Пароль має містити хоча б одну цифру.")

        has_special_char = any(not char.isalnum() for char in value)

        if not has_special_char:

            raise serializers.ValidationError("Пароль повинен містити хоча б один спеціальний символ.")

        return value

    def validate(self, attrs):

        if attrs['password'] != attrs['confirm_password']:

            raise serializers.ValidationError({"confirm_password": "Паролі мають збігатися."})


        return attrs

    def create(self, validated_data):

        validated_data.pop('confirm_password')

        user = ToDoUser(**validated_data)

        user.set_password(validated_data['password'])

        user.save()

        return user


class AuthorizationSerializer(serializers.Serializer):

    """Serializer for user's login request"""

    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):

        username = attrs.get('username')
        password = attrs.get('password')

        if username is None or password is None:
            raise serializers.ValidationError({
                                        "errors": {
                                            "username": "Це поле обов'язкове.",
                                            "password": "Це поле обов'язкове."
                                            }
                                        })

        user = authenticate(username=username, password=password)

        if user is None:

            try:
                user = ToDoUser.objects.get(username=username)

            except ToDoUser.DoesNotExist:

                raise serializers.ValidationError({"username": "Користувач не існує."})

            raise serializers.ValidationError({"password": "Неправильний пароль."})

        attrs['user'] = user

        return attrs


class ResetPasswordSerializer(serializers.Serializer):

    email = serializers.EmailField()

    def validate_email(self, value):

        try:

            user = ToDoUser.objects.get(email=value)

        except ToDoUser.DoesNotExist:

            raise serializers.ValidationError("Користувач не існує.")

        else:

            return value


    def save(self):

        email = self.validated_data['email']

        user = get_user_model().objects.get(email=email)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_url = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
        full_url = f'{settings.FRONTEND_URL}{reset_url}'


        send_mail(

            'Password Reset Request',
            f'Click the link to reset your password: {full_url}',
            'todo@gmail.com',
            [user.email]
        )


class ResetPasswordConfirmSerializer(serializers.Serializer):

    uibd64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField()

    def validate(self, data):
        print(data)
        try:

            uid = urlsafe_base64_decode(data['uibd64']).decode('utf-8')

            user = get_user_model().objects.get(pk=uid)

        except (TypeError, ValueError, get_user_model().DoesNotExist):

            raise serializers.ValidationError('Неправильний користувач.')

        token = data['token']

        if not default_token_generator.check_token(user, token):

            raise serializers.ValidationError({'server': 'Неправильний чи прострочений токен.'})

        return data

    def save(self):

        uid = urlsafe_base64_decode(self.validated_data['uibd64']).decode('utf-8')

        user = get_user_model().objects.get(pk=uid)

        user.set_password(self.validated_data['new_password'])

        user.save()

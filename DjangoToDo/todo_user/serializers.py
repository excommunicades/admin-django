from rest_framework import serializers, status
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.http import JsonResponse

from django.contrib.auth import authenticate

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

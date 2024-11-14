import uuid
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.views import exception_handler
from rest_framework.exceptions import ValidationError

from django.shortcuts import redirect
from django.conf import settings
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.core.mail import send_mail
from django.core.cache import cache

from users.serializers import (
    RegistrationSerializer,
    AuthorizationSerializer,
    ResetPasswordSerializer,
    ResetPasswordConfirmSerializer,
    )

from users.services.services_views import (
    register_user,
    activate_email,
    login_user
)

from users.models import ToDoUser





class Register_User(generics.CreateAPIView):

    """Endpoint for user registration"""

    serializer_class = RegistrationSerializer

    def create(self, request, *args, **kwargs):

        """Check validation of form, create user"""
        
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():

            user_data = serializer.validated_data

            token = register_user(user_data)

            cache.set(token, user_data, timeout=180)

            request.session['user_data'] = user_data
            request.session['verification_token'] = token

            return Response(
                {"message": "Реєстрація успішна. Будь ласка, перевірте вашу пошту на лист для підтвердження."},
                status=status.HTTP_200_OK
            )

        errors = serializer.errors

        formatted_errors = {}

        if errors.get("username"):

            if errors["username"][0] == 'to do user with this username already exists.':

                formatted_errors["username"] = 'Користувач із таким іменем вже існує.'

            elif errors["username"][0] == 'This field is required.':

                formatted_errors["username"] = 'Це поле є обов\'язковим'

            else:
                formatted_errors["username"] = errors["username"][0]

        if errors.get("email"):

            if errors["email"][0] == 'to do user with this email already exists.':

                formatted_errors["email"] = 'Користувач із цією електронною адресою вже існує.'

            elif errors["email"][0] == "Це поле обов'язкове.":

                formatted_errors["email"] = "Це поле обов'язкове."

            else:

                formatted_errors["email"] = errors["email"][0]

        if errors.get("password"):
            formatted_errors["password"] = errors["password"][0]

        if errors.get("confirm_password"):

            if errors["confirm_password"][0] == 'This field is required.':

                errors["confirm_password"][0] = 'Це поле є обов\'язковим'

            formatted_errors["confirm_password"] = errors["confirm_password"][0]

        return Response(
            {"errors": formatted_errors},
            status=status.HTTP_400_BAD_REQUEST
        )


class Activate_email(generics.GenericAPIView):

    def post(self, request, token, *args, **kwargs):

        user = activate_email(token)

        if user:

            return Response({"message": "Електронну пошту успішно перевірено та користувача зареєстровано!"}, status=status.HTTP_201_CREATED)

        else:

            return Response({"errors": {"message": "У сеансі відсутні дані користувача"}}, status=status.HTTP_400_BAD_REQUEST)


class Login_User(generics.GenericAPIView):

    """Endpoint for user authentication"""

    serializer_class = AuthorizationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            errors = serializer.errors
            formatted_errors = {}
            print(errors)
            if errors.get('username'):
                username_error = str(errors['username'][0])

                if username_error == 'Користувач не існує.':

                    formatted_errors['username'] = 'Користувач не існує.'

                elif username_error == "This field is required.":

                    formatted_errors['username'] = "Це поле обов'язкове."

                else:

                    formatted_errors['username'] = username_error

            if errors.get('password'):

                password_error = str(errors['password'][0])

                if password_error == 'Неправильний пароль.':
                    formatted_errors['password'] = 'Неправильний пароль.'

                if password_error == 'This field is required.':

                    formatted_errors['password'] = 'Це поле обов\'язкове.'

                else:
                    formatted_errors['password'] = password_error

            return Response({'errors': formatted_errors}, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']

        login_response = login_user(user)

        if login_response:

            return Response(login_response, status=status.HTTP_200_OK)

        else:
            
            return Response({'errors': {'username': 'Користувач не знайдений'}}, status=status.HTTP_404_NOT_FOUND)

class Reset_password(generics.GenericAPIView):

    """Endpoint for letter submitting"""

    def post(self, request, *args, **kwargs):
        serializer = ResetPasswordSerializer(data=request.data)

        # Проверяем валидность данных
        if not serializer.is_valid():

            errors = serializer.errors
            formatted_errors = {}

            if errors.get('email'):
                email_error = str(errors['email'][0])

                if email_error == 'Користувач не існує.':

                    formatted_errors['email'] = 'Користувач не існує.'

                elif email_error == 'This field is required.':

                    formatted_errors['email'] = 'Це поле обов\'язкове.'

                elif email_error == 'Enter a valid email address.':

                    formatted_errors['email'] = 'Введіть корректну пошту.'

                else:

                    formatted_errors['email'] = email_error

            return Response({'errors': formatted_errors}, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()

        return Response({'message': 'Посилання для зміни пароля надіслано на вашу електронну адресу.'}, status=status.HTTP_200_OK)


class Reset_confirm_password(generics.GenericAPIView):

    """Endpoint for confirming password"""

    serializer_class = ResetPasswordConfirmSerializer

    def post(self, request, *args, **kwargs):

        serializer = ResetPasswordConfirmSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():

            serializer.save()

            return Response({"message": "Пароль був змінений успішно"}, status=status.HTTP_205_RESET_CONTENT)
        
        else:

            if serializer.errors.get('server')[0] == 'Неправильний чи прострочений токен.':

                return Response({"errors": {"new_password": 'Неправильний чи прострочений токен.'}},status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

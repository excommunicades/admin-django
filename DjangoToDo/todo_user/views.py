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

from todo_user.serializers import (
    RegistrationSerializer,
    AuthorizationSerializer,
    ResetPasswordSerializer,
    ResetPasswordConfirmSerializer,
    )

from todo_user.models import ToDoUser


def custom_exception_handler(exc, context):

    response = exception_handler(exc, context)

    if response is not None and isinstance(exc, ValidationError):

        for field, messages in response.data.items():
            if isinstance(messages, list):
                response.data[field] = ' '.join(messages)

        response.data = {"errors": response.data}

    if isinstance(exc, ValidationError):
        print(response.data)
        errors = response.data.get('errors')
        print(errors)
        if errors.get('email') == "User with this email already exists":

            response = Response(response.data,
                status=status.HTTP_409_CONFLICT
            )

            return response

        if errors.get('username') == "User with this username already exists":

            response = Response(response.data,
                status=status.HTTP_409_CONFLICT
            )

            return response

        return response

class Register_User(generics.CreateAPIView):

    """Endpoint for user registration"""

    serializer_class = RegistrationSerializer

    def create(self, request, *args, **kwargs):

        """Check validation of form, create user"""

        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():

            token = uuid.uuid4().hex
            user_data = serializer.validated_data
            
            request.session['user_data'] = user_data
            request.session['verification_token'] = token
            
            verification_url = f"{settings.FRONTEND_URL}/verify-email/{token}/"
            send_mail(
                subject="Підтвердження Email",
                message=f"Привіт, {user_data['username']}! Для підтвердження вашої електронної пошти перейдіть за посиланням: {verification_url}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user_data['email']],
                ) 
            print('request.session.values():',request.session.values())


        if not serializer.is_valid():
            errors = serializer.errors
            print(errors)

            if errors.get("password"):
                data = {"password": errors["password"][0]}
                return Response({"errors": data}, status=status.HTTP_400_BAD_REQUEST)

            if errors.get("username"):
                error = 'error'
                if errors['username'][0] == 'to do user with this username already exists.':
                    error = 'Користувач із таким іменем вже існує.'
                data = {"username": error}
                return Response({"errors": data}, status=status.HTTP_409_CONFLICT)

            if errors.get("email"):
                error = 'error'
                if errors['email'][0] == 'to do user with this email already exists.':
                    error = 'Користувач із цією електронною адресою вже існує.'
                if errors['email'][0] == "Це поле обов'язкове.":
                    error = "Це поле обов'язкове."
                data = {"email": error}
                return Response({"errors": data}, status=status.HTTP_409_CONFLICT)

            if errors.get("confirm_password"):
                data = {"confirm_password": errors["confirm_password"][0]}
                return Response({"errors": data}, status=status.HTTP_409_CONFLICT)

            return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)

        # self.perform_create(serializer)

        return Response({"message": "Registration successful.Будь ласка перевірте вашу пошту на лист за підтвердженням."}, status=status.HTTP_200_OK)


class Login_User(generics.GenericAPIView):

    """Endpoint for user authentication"""

    serializer_class = AuthorizationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            errors = serializer.errors
            print(errors)
            if errors.get('username'):

                username_error = str(errors['username'][0])
                print(username_error)
                if username_error == 'Користувач не існує.':
                    return Response({'errors': {'username': 'Користувач не існує.'}}, status=status.HTTP_404_NOT_FOUND)
                if username_error == "Це поле обов'язкове.":
                    return Response({'errors': {'username': "Це поле обов'язкове."}}, status=status.HTTP_404_NOT_FOUND)

            if errors.get('password'):

                password_error = str(errors['password'][0])
                if password_error == 'Неправильний пароль.':
                    return Response({'errors': {'password': 'Неправильний пароль.'}}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({'errors': errors}, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)

        user_data = ToDoUser.objects.get(username=str(user))

        return Response({
            'refresh_token': str(refresh),
            'access_token': str(refresh.access_token),
            "user": {
                "username": user_data.username,
                "pk": user_data.pk,
                "email": user_data.email
            }
        })


class Reset_password(generics.GenericAPIView):

    """Endpoint for letter submitting"""

    def post(self, request, *args, **kwargs):

        serializer = ResetPasswordSerializer(data=request.data)

        if not serializer.is_valid():
            if serializer.errors.get('email')[0] == 'Користувач не існує.':
                return Response({'errors': {"email": "Користувач не існує."}}, status.HTTP_404_NOT_FOUND)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password reset link has been sent to your email.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
                print(serializer.errors.get('server')[0])
                return Response({"errors": {"new_password": 'Неправильний чи прострочений токен.'}},status=status.HTTP_400_BAD_REQUEST)
            print(serializer.errors.get('server')[0])

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Activate_email(generics.GenericAPIView):

    def post(self, request, token, *args, **kwargs):

        print('token:',token)
        session_token = request.session.get('verification_token')
        print('session_token:',session_token)
        print("sessiond_data:", request.session.values())
        if session_token == token:
            user_data = request.session.get('user_data')

            if user_data:

                user = ToDoUser.objects.create_user(
                    username=user_data['username'],
                    email=user_data['email'],
                    password=user_data['password']
                )

                request.session.flush()

                return Response({"message": "Email successfully verified and user registered!"}, status=status.HTTP_201_CREATED)

            else:

                return Response({"error": "No user data in session"}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({"error": "Invalid token or expired link"}, status=status.HTTP_400_BAD_REQUEST)

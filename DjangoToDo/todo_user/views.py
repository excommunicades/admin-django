from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.views import exception_handler
from rest_framework.exceptions import ValidationError


from django.db import IntegrityError

from todo_user.serializers import (
    RegistrationSerializer,
    AuthorizationSerializer,
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

        self.perform_create(serializer)

        return Response(serializer.data, status=status.HTTP_201_CREATED)


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

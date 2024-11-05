from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from django.urls import path

from todo_user.views import (
    Register_User,
    Login_User
)

urlpatterns = [
    path('register', Register_User.as_view(), name="user_registration"),
    path('login', Login_User.as_view(), name="user_authorization"),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
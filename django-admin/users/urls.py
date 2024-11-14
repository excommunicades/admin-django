from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from django.urls import path

from users.views import (
    Register_User,
    Login_User,
    Reset_password,
    Reset_confirm_password,
    Activate_email,
)

urlpatterns = [
    path('register/', Register_User.as_view(), name="user_registration"),
    path('login/', Login_User.as_view(), name="user_authorization"),
    path('reset-password/', Reset_password.as_view(), name="password_reset"),
    path('reset-password-confirm/<uidb64>/<token>/', Reset_confirm_password.as_view(), name='password_reset_confirm'),
    path('verify-email/<str:token>/', Activate_email.as_view(), name='verify-email'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

]
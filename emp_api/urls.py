from django.urls import path
from rest_framework_simplejwt import views as jwt_views

from .views import (
    SuperUserManagerRegistration,
    UserLoginAPIView,
    GetUserListView,
    LogoutAPI
)

urlpatterns = [
    path('token/obtain/', jwt_views.TokenObtainPairView.as_view(), name='token_create'),
    path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('register', SuperUserManagerRegistration.as_view(), name='register'),
    path('login', UserLoginAPIView.as_view(), name='login'),
    path('users', GetUserListView.as_view(), name='users'),
    path('logout', LogoutAPI.as_view(), name='logout'),
]

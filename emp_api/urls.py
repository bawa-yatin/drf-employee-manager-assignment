from django.urls import path
from rest_framework_simplejwt import views as jwt_views

from .views import (
    SuperUserManagerRegistration,
    UserLoginAPIView,
    GetUserListView,
    EmpRegistration,
    GetEmpListView,
    UpdateEmpView,
    DeleteEmpView,
    LogoutAPI
)

urlpatterns = [
    path('token/obtain/', jwt_views.TokenObtainPairView.as_view(), name='token_create'),
    path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('register', SuperUserManagerRegistration.as_view(), name='register'),
    path('login', UserLoginAPIView.as_view(), name='login'),
    path('users', GetUserListView.as_view(), name='users'),
    path('emp/register', EmpRegistration.as_view(), name='emp_register'),
    path('emp/all', GetEmpListView.as_view(), name='emp_list'),
    path('emp/delete/<pk>', DeleteEmpView.as_view(), name='user-delete'),
    path('emp/update/<pk>', UpdateEmpView.as_view(), name='user-update'),
    path('logout', LogoutAPI.as_view(), name='logout'),
]

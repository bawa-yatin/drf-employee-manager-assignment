from rest_framework import status
from rest_framework.generics import (GenericAPIView,
                                     CreateAPIView,
                                     UpdateAPIView,
                                     DestroyAPIView,
                                     ListAPIView)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from .models import CompanyUser
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserListSerializer,
    EmpRegistrationSerializer,
    EmpUpdateSerializer,
    EmpListSerializer,
    EmpProfileSerializer,
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    LogoutSerializer,
)


# Method for generating access and refresh token after successful registration
def get_tokens_after_user_registration(user):
    refresh = RefreshToken.for_user(user)
    return ({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    })


# View class for registration of SuperUser/Manager. Access and refresh token will
# be generated on successful registration
class SuperUserManagerRegistration(CreateAPIView):
    serializer_class = UserRegistrationSerializer

    def post(self, request, *args, **kwargs):
        print("REQUEST DATA", request.data)
        serializer = self.serializer_class(data=request.data)
        valid = serializer.is_valid(raise_exception=True)

        if valid:
            user = serializer.save()
            token = get_tokens_after_user_registration(user)
            status_code = status.HTTP_201_CREATED

            response = {
                'success': True,
                'statusCode': status_code,
                'message': 'User successfully registered!',
                'user': serializer.data,
                'token': token
            }

            return Response(response, status=status_code)
        else:
            return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)


# View class for every user to log into his account by providing credentials
# Access and refresh token will be generated on successful login
class UserLoginAPIView(GenericAPIView):
    serializer_class = UserLoginSerializer

    def post(self, request, *args, **kwargs):
        print("REQUEST DATA", request.data)
        serializer = self.serializer_class(data=request.data)
        valid = serializer.is_valid(raise_exception=True)

        if valid:
            status_code = status.HTTP_200_OK

            response = {
                'success': True,
                'statusCode': status_code,
                'message': 'User logged in successfully',
                'access': serializer.data['access'],
                'refresh': serializer.data['refresh'],
                'authenticatedUser': {
                    'email': serializer.data['email'],
                    'role': serializer.data['role']
                }
            }

            return Response(response, status=status_code)
        else:
            return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)


# View class for getting list of all Managers/Employees registered(Can be accessed by
# SuperUser only)
class GetUserListView(ListAPIView):
    serializer_class = UserListSerializer
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = request.user
        if user.role != "SUPERUSER":
            response = {
                'success': False,
                'status_code': status.HTTP_403_FORBIDDEN,
                'message': 'You are not authorized to perform this action'
            }
            return Response(response, status.HTTP_403_FORBIDDEN)
        else:
            users = CompanyUser.objects.filter(is_superuser="False")
            if users.count() >= 1:
                serializer = self.serializer_class(users, many=True)
                response = {
                    'success': True,
                    'status_code': status.HTTP_200_OK,
                    'message': 'Successfully fetched users',
                    'users': serializer.data

                }
                return Response(response, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'No users available in this category!'}, status=status.HTTP_204_NO_CONTENT)


# View class for creating new Employee(Can be done by registered Managers only)
# Employee will get login credentials on his email address after registration
class EmpRegistration(CreateAPIView):
    serializer_class = EmpRegistrationSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        user = request.user
        if user.role != "MANAGER":
            response = {
                'success': False,
                'status_code': status.HTTP_403_FORBIDDEN,
                'message': 'You are not authorized to perform this action'
            }
            return Response(response, status.HTTP_403_FORBIDDEN)
        else:
            print("REQUEST DATA", request.data)
            serializer = self.serializer_class(data=request.data)
            valid = serializer.is_valid(raise_exception=True)

            if valid:
                serializer.save()
                status_code = status.HTTP_201_CREATED

                response = {
                    'success': True,
                    'statusCode': status_code,
                    'message': 'Employee successfully registered! Please check mail for credentials!',
                    'user': serializer.data,
                }

                return Response(response, status=status_code)
            else:
                return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)


# View class for getting list of all Employees registered(Can be performed by
# Manager only)
class GetEmpListView(ListAPIView):
    serializer_class = EmpListSerializer
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = request.user
        if user.role != "MANAGER":
            response = {
                'success': False,
                'status_code': status.HTTP_403_FORBIDDEN,
                'message': 'You are not authorized to perform this action'
            }
            return Response(response, status.HTTP_403_FORBIDDEN)
        else:
            users = CompanyUser.objects.filter(role="EMPLOYEE")
            if users.count() >= 1:
                serializer = self.serializer_class(users, many=True)
                response = {
                    'success': True,
                    'status_code': status.HTTP_200_OK,
                    'message': 'Successfully fetched users',
                    'users': serializer.data

                }
                return Response(response, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'No employees available in this category!'},
                                status=status.HTTP_204_NO_CONTENT)


# View class for updating details of an existing employee(Can be performed by
# Manager only)
class UpdateEmpView(UpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmpUpdateSerializer

    def get_queryset(self):
        user_id = self.kwargs['pk']
        return CompanyUser.objects.filter(id=user_id)

    def patch(self, request, *args, **kwargs):
        user = request.user
        if user.role != "MANAGER":
            response = {
                'success': False,
                'status_code': status.HTTP_403_FORBIDDEN,
                'message': 'You are not authorized to perform this action'
            }
            return Response(response, status.HTTP_403_FORBIDDEN)
        else:
            instance = self.get_object()
            instance.first_name = request.data["first_name"]
            instance.last_name = request.data["last_name"]
            instance.date_of_birth = request.data["date_of_birth"]
            instance.address = request.data["address"]
            instance.contact_number = request.data["contact_number"]

            serializer = self.get_serializer(instance, data=request.data)

            if serializer.is_valid(raise_exception=True):
                self.partial_update(serializer)

            response = {
                'success': True,
                'message': 'Employee updated successfully!',
                'user': serializer.data
            }

            return Response(response, status=status.HTTP_200_OK)


# View class for deleting an existing employee(Can be performed by Manager only)
class DeleteEmpView(DestroyAPIView):
    permission_classes = (IsAuthenticated,)

    def delete(self, request, *args, **kwargs):
        user = request.user
        if user.role != "MANAGER":
            response = {
                'success': False,
                'status_code': status.HTTP_403_FORBIDDEN,
                'message': 'You are not authorized to perform this action'
            }
            return Response(response, status.HTTP_403_FORBIDDEN)
        else:
            user_id = self.kwargs["pk"]
            user_profile = CompanyUser.objects.filter(id=user_id)
            serializer = EmpProfileSerializer(user_profile, many=True)

            if serializer.data[0]["role"] == "SUPERUSER" or serializer.data[0]["role"] == "MANAGER":
                return Response({'message': 'You cannot delete any superuser or manager!'}, status.HTTP_403_FORBIDDEN)
            else:
                user_profile.delete()
                return Response({'message': 'Employee Deleted Successfully!'}, status.HTTP_204_NO_CONTENT)


# Serializer class for getting profile details of logged-in user(Can be accessed by
# all types of authenticated users)
class GetEmpProfile(ListAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        serializer = EmpProfileSerializer(request.user)
        response = {
            'success': True,
            'status_code': status.HTTP_200_OK,
            'message': 'User Details',
            'users': serializer.data

        }
        return Response(response, status=status.HTTP_200_OK)


# View class for sending a reset password link in case of forgotten password
class ForgotPassword(GenericAPIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'message': 'Check email for password reset link!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# View class for resetting password using link received
class ResetPassword(GenericAPIView):
    def post(self, request, uid, token):
        serializer = ResetPasswordSerializer(data=request.data, context={
            'uid': uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({'message': 'Password reset successful!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# View class for blacklisting refresh token on User Logout
class LogoutAPI(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated, ]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({'message': 'Logout Successful!'}, status=status.HTTP_200_OK)

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


def get_tokens_after_user_registration(user):
    refresh = RefreshToken.for_user(user)
    return ({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    })


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
            users = CompanyUser.objects.filter(role="MANAGER")
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
                user = serializer.save()
                token = get_tokens_after_user_registration(user)
                status_code = status.HTTP_201_CREATED

                response = {
                    'success': True,
                    'statusCode': status_code,
                    'message': 'Employee successfully registered! Please check mail for credentials!',
                    'user': serializer.data,
                    'token': token
                }

                return Response(response, status=status_code)
            else:
                return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)


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
                return Response({'message': 'No users available in this category!'}, status=status.HTTP_204_NO_CONTENT)


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
            instance.email = request.data["email"]
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
            CompanyUser.objects.filter(id=user_id).delete()
            return Response({'message': 'Employee Deleted Successfully!'}, status.HTTP_204_NO_CONTENT)


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


class ForgotPassword(GenericAPIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'message': 'Check email for password reset link!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPassword(GenericAPIView):

    def post(self, request, uid, token):
        serializer = ResetPasswordSerializer(data=request.data, context={
            'uid': uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({'message': 'Password reset successful!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutAPI(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated, ]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({'message': 'Logout Successful!'}, status=status.HTTP_200_OK)

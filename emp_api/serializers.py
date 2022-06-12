from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .models import CompanyUser


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyUser
        fields = (
            'email',
            'first_name',
            'last_name',
            'date_of_birth',
            'address',
            'contact_number',
            'role',
            'password'
        )
        extra_kwargs = {
            'password': {'write_only': True},
        }

    default_error_messages = {
        'bad_request': 'Employee can only be created by Manager!'
    }

    def create(self, validated_data):
        if validated_data['role'] == "SUPERUSER":
            auth_user = CompanyUser.objects.create_superuser(**validated_data)
            return auth_user
        elif validated_data['role'] == "MANAGER":
            auth_user = CompanyUser.objects.create_user(**validated_data)
            return auth_user
        else:
            self.fail('bad_request')


class EmpRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyUser
        fields = (
            'email',
            'first_name',
            'last_name',
            'date_of_birth',
            'address',
            'contact_number',
            'role',
        )

    default_error_messages = {
        'bad_request': 'SuperUser/Manager cannot be created from this form!'
    }

    def create(self, validated_data):
        if validated_data['role'] == "SUPERUSER" or validated_data['role'] == "MANAGER":
            self.fail('bad_request')
        else:
            auth_user = CompanyUser.objects.create_user(**validated_data,
                                                        password=CompanyUser.objects.make_random_password())
            return auth_user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(max_length=128, write_only=True)
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)
    role = serializers.CharField(read_only=True)

    def validate(self, data):
        email = data['email']
        password = data['password']
        user = authenticate(email=email, password=password)

        if user is None:
            raise serializers.ValidationError("Invalid login credentials")
        else:
            refresh = RefreshToken.for_user(user)
            refresh_token = str(refresh)
            access_token = str(refresh.access_token)

            update_last_login(None, user)

            validation = {
                'access': access_token,
                'refresh': refresh_token,
                'email': user.email,
                'role': user.role,
            }

            return validation


class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyUser
        fields = (
            'email',
            'first_name',
            'last_name',
            'role',
        )


class EmpListSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyUser
        fields = (
            'email',
            'first_name',
            'last_name',
            'role',
        )


class EmpUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyUser
        fields = ('id',
                  'email',
                  'first_name',
                  'last_name',
                  'date_of_birth',
                  'address',
                  'contact_number', )


# Logout Serializer for blacklisting refresh token on User Logout
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    default_error_messages = {
        'bad_token': 'Token is expired or invalid!'
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')

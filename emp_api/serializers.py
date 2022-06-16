import pytz
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import timezone
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .models import CompanyUser
from .utils import Util


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

            login_data = {
                'access': access_token,
                'refresh': refresh_token,
                'email': user.email,
                'role': user.role,
            }

            return login_data


class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyUser
        fields = (
            'email',
            'first_name',
            'last_name',
            'role',
        )


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
        'bad_request': 'SuperUser / Manager cannot be created from this form!'
    }

    def create(self, validated_data):
        if validated_data['role'] == "SUPERUSER" or validated_data['role'] == "MANAGER":
            self.fail('bad_request')
        else:
            emp_password = CompanyUser.objects.make_random_password()
            auth_user = CompanyUser.objects.create_user(**validated_data,
                                                        password=emp_password)

            body = ''' Hi there...We're thrilled to have you on board! You can use the following credentials to log into your 
            account. ''' + '\n\n' + 'Email Address: ' + validated_data[
                'email'] + '\n' + 'Password: ' + emp_password + '\n\n' + 'Thanks & Regards! '
            data = {
                'subject': 'Welcome On-Board' + ' ' + validated_data['first_name'] + ' ' + validated_data['last_name'],
                'body': body,
                'to_email': validated_data['email']
            }
            Util.send_email(data)
            return auth_user


class EmpProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyUser
        fields = ['id', 'email', 'first_name', 'last_name', 'date_of_birth', 'contact_number', 'role']


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
                  'contact_number',)


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    default_error_messages = {
        'bad_user': 'You are not a registered User!'
    }

    class Meta:
        fields = ['email']

    def validate(self, data):
        email = data.get('email')
        if CompanyUser.objects.filter(email=email).exists():
            user = CompanyUser.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))

            token = PasswordResetTokenGenerator().make_token(user)
            link = 'http://127.0.0.1:8000/api/reset/' + uid + '/' + token + '/'

            body = 'Click the link to reset password: ' + link
            data = {
                'subject': 'Request for Password Reset',
                'body': body,
                'to_email': user.email}
            Util.send_email(data)
            return data

        else:
            self.fail('bad_user')


class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)

    password2 = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)

    default_error_messages = {
        'bad_token': 'Token is invalid or expired!'
    }

    class Meta:
        fields = ['password', 'password2']

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        uid = self.context.get('uid')
        token = self.context.get('token')

        if password != password2:
            raise serializers.ValidationError("Password doesn't Match")

        id = smart_str(urlsafe_base64_decode(uid))
        user = CompanyUser.objects.get(id=id)

        # utc_now = timezone.now()
        # utc_now = utc_now.replace(tzinfo=pytz.utc)

        if not PasswordResetTokenGenerator().check_token(user, token):
            self.fail('bad_token')
        # elif token.created < utc_now - settings.TOKEN_TTL:
        #     self.fail('bad_token')

        user.set_password(password)
        user.save()
        return data


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

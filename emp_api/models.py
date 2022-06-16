from django.db import models
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import AbstractBaseUser
from django.utils import timezone

from .managers import CustomUserManager


# Create your models here.
class CompanyUser(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ("SUPERUSER", 'Super User'),
        ("MANAGER", 'Manager'),
        ("EMPLOYEE", 'Employee')
    )

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'

    email = models.EmailField(unique=True, max_length=100)
    first_name = models.CharField(max_length=30, blank=False)
    last_name = models.CharField(max_length=50, blank=False)
    date_of_birth = models.DateField()
    address = models.CharField(max_length=200, blank=False)
    contact_number = models.CharField(unique=True, max_length=10)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, blank=False, default="SUPERUSER")
    date_joined = models.DateTimeField(auto_now_add=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    created_date = models.DateTimeField(default=timezone.now)
    modified_date = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email

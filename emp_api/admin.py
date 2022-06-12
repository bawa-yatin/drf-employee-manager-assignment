from django.contrib import admin
from .models import CompanyUser
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin


# Register your models here.


class UserModelAdmin(BaseUserAdmin):
    # The forms to add and change user instances

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('email',
                    'first_name',
                    'last_name',
                    'date_of_birth',
                    'address',
                    'contact_number',
                    'is_staff', 'is_active',)
    list_filter = ('email', 'is_staff', 'is_active', 'is_superuser')
    fieldsets = (
        ('User_Credentials', {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'date_of_birth', 'address', 'contact_number')}),
        ('Permissions', {'fields': ('role', 'is_staff', 'is_active', 'is_superuser')}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name',
                       'last_name',
                       'date_of_birth',
                       'address',
                       'contact_number',
                       'role', 'password1', 'password2', 'is_staff', 'is_active'),
        }),
    )
    search_fields = ('email',)
    ordering = ('id',)
    filter_horizontal = ()


# Now register the new UserAdmin...
admin.site.register(CompanyUser, UserModelAdmin)

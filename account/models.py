from django.db import models

from django.db import models
from helpers.models import TrackingModel

# Create your models here.
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils.translation import gettext as _
# from phonenumber_field.modelfields import PhoneNumberField
from django.urls import reverse
from enum import Enum

# CREATE CUSTOM USER MANAGER TO BE EXTENDED BY USER
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", False)
        extra_fields.setdefault("is_verified", False)
        if email is None:
            raise TypeError(_("User should have an Email"))

        user = self.model(email=email, password=password, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_verified", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser has to have is_staff True")

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser has to have is_superuser True")

        return self.create_user(email=email, password=password, **extra_fields)


# MY CUSTOM USER
class User(AbstractUser, TrackingModel, PermissionsMixin):

    email = models.CharField(max_length=255, unique=True)
    username = models.CharField(max_length=255, null=True)
    # phone_number = PhoneNumberField(null=True)
    is_verified = models.BooleanField(default=False)
    is_auto_generate_password = models.BooleanField(default=False)
    change_password_on_first_signin = models.BooleanField(default=False)
    profile_image = models.ImageField(
        upload_to="profile_image//%Y/%m/%d", blank=True, null=True
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]
    objects = CustomUserManager()

    class Meta:
        ordering = ["-created_at"]
        permissions = [
            ["deactivate_user", "can deactivate user"],
            ["print_user", "can print user"],
            ["import_user", "can import user"],
            ["export_user", "can export user"],
        ]

    def __str__(self):
        return self.email

    def get_absolute_url(self, *args, **kwargs):
        return reverse("User:detail", kwargs={"email": self.email})


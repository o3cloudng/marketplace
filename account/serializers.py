from enum import unique

from django.conf import settings
from django.contrib.auth.models import ContentType, Group, Permission
# from rest_framework.validators import UniqueValidator
# Password Reset Utils
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.forms import CharField
from django.urls import reverse
from django.utils.encoding import (DjangoUnicodeDecodeError, force_str,
                                   smart_bytes, smart_str)
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers, status
from rest_framework_simplejwt.serializers import (TokenObtainPairSerializer,
                                                  TokenObtainSerializer)
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from account.models import User  # Permission, Role, UserRole


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer, TokenObtainSerializer):
    
    # Overiding validate function in the TokenObtainSerializer  
    def validate(self, attrs):
        authenticate_kwargs = {
            self.username_field: attrs[self.username_field],
            'password': attrs['password'],
        }
        try:
            authenticate_kwargs['request'] = self.context['request']
        except KeyError:
            pass

        # print(f"\nthis is the user of authenticate_kwargs {authenticate_kwargs['email']}\n")
       
        try:
         user = User.objects.get(email=authenticate_kwargs['email'])
         if not user.is_active:
             self.error_messages['no_active_account']=_(
                 'The account is inactive'
             )
             raise exceptions.AuthenticationFailed(
                 self.error_messages['no_active_account'],
                 'no_active_account',
             )
        except User.DoesNotExist:
          self.error_messages['no_active_account'] =_(
              'Error with the email, ensure you enter the correct email address')
          raise exceptions.AuthenticationFailed(
              self.error_messages['no_active_account'],
              'no_active_account',
          )
        else:
            self.error_messages['no_active_account'] =_(
              'Error with the password, ensure you enter the correct password')

        
        return super().validate(attrs)




class GroupSerializer(serializers.ModelSerializer):
    name = CharField(max_length=100)
    class Meta:
        model = Group
        fields = ["id","name"]

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(default="#1Million", write_only=True) # write_only=True
    email = serializers.EmailField(allow_blank=False)
    is_verified = serializers.BooleanField(default=True)
    # groups = GroupSerializer(many=True) #
    # groups = serializers.StringRelatedField(queryset=User.objects.all(), many=True)
    # role = GroupSerializer()
    # username = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "profile_image",
            # "username",
            "password",
            "is_verified",
            "is_auto_generate_password", # Either send password in plain text or as token
            "change_password_on_first_signin",
            "created_at",
            "updated_at"
        ]


    def validate_email(self, email):
        is_already_exists = User.objects.filter(email=email).exists()
        if is_already_exists:
            raise serializers.ValidationError("Email already exists")
        return email

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class UserUpdateSerializer(serializers.ModelSerializer):
    # profile_image = serializers.ImageField()
    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            # "phone_number",
        ]
    def validate_email(self, email):
        is_already_exists = User.objects.filter(email=email).exists()
        if is_already_exists:
            raise serializers.ValidationError("Email already exists")
        return email


class ProfileImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["profile_image"]
        

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=200, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ["password","token","uidb64"]

    def validate(self, attrs):
        try:
            password = attrs.get("password")
            token = attrs.get("token")
            uidb64 = attrs.get("uidb64")

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise exceptions.AuthenticationFailed("The reset link is invalid", 401)
                # return Response()
            user.set_password(password)
            user.change_password_on_first_signin = False
            user.save()
            return (user)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed("User or reset link is invalid", 401)
        return super().validate(attrs)


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)
    class Meta:
        fields = ["email"]

    # def validate(self, attrs):
    #     try:
    #         email = attrs["email", ""]
    #         if User.objects.filter(email=email).exists():
    #             user = User.objects.get(email=email)
    #             uidb64 = urlsafe_base64_encode(user.id)
    #             token = PasswordResetTokenGenerator().make_token(user)

    #             base_url = settings.ARGUEHOST + "confirm-password-reset/?token="+str(token)

    #             email_body = (
    #                 "Hello "
    #                 + user.first_name + " "+user.last_name + ",\n\n"
    #                 + "Your account password on ARGUE has been reset.\n\n"
    #                 + "Below is your link to verify it is you.\n\n\n\n"

    #                 # + "Email: " + user.email + "\n\n"
    #                 + base_url
                    
    #                 +"\n\n\n\n"
    #                 + "Please set new password after clicking the link.\n\n"
    #             )
    #             data = {
    #                 "email_body": email_body,
    #                 "to_email": user.email,
    #                 "email_subject": "ARGUE: Password Reset",
    #             }

    #             Util.send_email(data)

    #         return attrs
    #     except expression as identifier:
    #         pass
    #     return super().validate(attrs)


class ChangePasswordSerializer(serializers.Serializer):
    model = User
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class ReactivateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["is_active"]

    def update(self, instance, validated_data):
        # instance.is_deleted = validated_data.get("is_deleted", instance.is_deleted)
        instance.save()
        return instance


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {"bad_token": ("Token is expired or invalid")}

    def validate(self, attrs):
        self.token = attrs["refresh"]
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail("bad_token")


# class RoleSerializer(serializers.ModelSerializer):
#     name = CharField(max_length=100, validators=[UniqueValidator(queryset=Group.objects.all())])
#     class Meta:
#         model = Group
#         fields = "__all__"


class ModuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = "__all__"



class RoleUserSerializer(serializers.Serializer):
    class Meta:
        # model = User
        fields = ["id", "first_name", "last_name"]

# Groups and Members
class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["first_name","last_name"]
class RolesUsersSerializer(serializers.ModelSerializer):
    name = CharField(max_length=100)
    users = UsersSerializer(many=True)
    class Meta:
        model = Group
        fields = ["id", "name", "users"]


class PermissionSerializer(serializers.ModelSerializer):
    codename = serializers.CharField(allow_blank=False)
    class Meta:
        model = Permission
        fields =["codename"]
class RolePermissionSerializer(serializers.ModelSerializer):
    name = CharField(max_length=100)
    permissions = PermissionSerializer(many=True)
    class Meta:
        model = Group
        fields = ["id", "name", "permissions"]
    
    def to_representation(self, instance):
        response = super().to_representation(instance)
        # print("###### RESPONSE")
        # response["permissions"] = instance.split("_")

        perms = []
        # for p in response["permissions"]:
        #     a,b = p["codename"].split("_")[0], p["codename"].split("_")[1]
        #     if a == "add":
        #         perms.append("can_add")
        #     elif a=="change":
        #         perms.append("can_edit")
        #     elif a == "view":
        #         perms.append("can_view")
        #     elif a == "delete":
        #         perms.append("can_delete")
        #     elif a == "import":
        #         perms.append("can_import")
        #     elif a == "export":
        #         perms.append("can_export")
        #     elif a == "deactivate":
        #         perms.append("can_deactivate")
        #     else:
        #         pass
                
        # print(perms)
    
        return response


class AddUserRoleSerializer(serializers.Serializer):
    class Meta:
        fields = ["user", "role"]



class ContentTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContentType
        fields = "__all__"


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "first_name",
            "last_name",
            "phone_number",
            "profile_image",
        ]


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "profile_image"
        ]

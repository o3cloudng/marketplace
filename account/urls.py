from django.urls import include, path
from rest_framework_simplejwt.views import TokenRefreshView

from account.views import *


urlpatterns = [
    path("signin/", MyTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    path("users/", AllUsersListAPIView.as_view(), name="users"),
    # path("users/", AllUserAPIView.as_view(), name="users"),
    
    path("signup/", RegisterListAPIView.as_view(), name="signup"),
    path("<int:id>/", UserDetailAPIView.as_view(), name="users"),
    path(
        "reactivate-user/<int:id>/",
        ReactivateAPIView.as_view(),
        name="reactivate-user",
    ),
    # path('delete/<int:id>', UserSoftDelete, name="delete"),
    path("verify-email/", VerifyEmail.as_view(), name="verify-email"),
    
    path(
        "password-reset/",
        PasswordResetAPIView.as_view(),
        name="password-reset",
    ),
    path(
        "confirm-password-reset/<uidb64>/<token>/",
        ConfirmPasswordResetAPIView.as_view(),
        name="confirm-password-reset",
    ),
    path(
        "password-reset-complete/",
        SetNewPasswordAPIView.as_view(),
        name="password-reset-complete",
    ),
    path("change-password/", ChangePasswordAPIView.as_view(), name="change-password"),
    # path("role-permission/", role_permission, name="role-permission-create"),
    path("role-permission/", RolePermissionListCreateAPIView.as_view(), name="role-permission-create"),
    path("role-permission/<int:id>/", RoleDetailAPIView.as_view(), name="role-permission-detail"),
    path("role-users/<str:role>/", RoleUsersAPIView.as_view(), name="role-user-detail"),
    path("roles-users/", RolesUsersAPIView.as_view(), name="roles-users-detail"),
    # path("role/", RoleListCreateAPIView.as_view(), name="role-list-create"),
    path(
        "add_roles_permissions/",
        PermissionAPIView.as_view(),
        name="add_roles_permission",
    ),
    path("add_user_role/", AddUserRoleAPIView.as_view(), name="add-user-role"),
    path("profile/", ProfileDetailsAPIView.as_view(), name="profile"),
    path("profile/<int:id>", ProfileDetailsAPIView.as_view(), name="profile-edit"),
]

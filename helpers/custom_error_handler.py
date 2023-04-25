# from cgitb import handler
from rest_framework.views import exception_handler

# from rest_framework.response import Response
# from rest_framework import status


def custom_exception_handler(exc, context):

    handlers = {
        "ValidationError": _handle_generic_errors,
        "Http404": _handle_generic_errors,
        "PermissionDenied": _handle_generic_errors,
        "NotAuthenticated": _handle_authentication_errors,
    }

    response = exception_handler(exc, context)

    if response is not None:
        # import pdb
        # pdb.set_trace()
        if (
            "MyTokenObtainPairView" in str(context["view"]) and exc.status_code == 401
        ):  # noqa
            response.status_code = 200
            response.data = {
                "error": "Incorrect user credentials",
                "status_code": response.status_code,
            }
        response.data["status_code"] = response.status_code

        # if (
        #     "RoleDetailAPIView" in str(context["view"]) and exc.status_code == 500
        # ):  # noqa
        #     print(context["view"])
        #     response.status_code = 500
        #     response.data = {
        #         "error": "Role not found",
        #         "status_code": response.status_code,
        #     }
        # response.data["status_code"] = response.status_code

        if ("RoleDetailAPIView" in str(context["view"])):
            print(context["view"])
            response.status_code = 404
            response.data = {
                "error": "Role not found",
                "status_code": response.status_code,
            }
        response.data["status_code"] = response.status_code

    exception_class = exc.__class__.__name__

    if exception_class in handlers:
        return handlers[exception_class](exc, context, response)
    else:
        return response


def _handle_authentication_errors(exc, context, response):
    response.data = {
        "error": "Please, login to proceed.",
        "status_code": response.status_code,
    }
    return response


def _handle_generic_errors(exc, context, response):
    return response

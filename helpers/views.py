from django.http import JsonResponse


def error_404(request, exception):
    message = "The endpoint is not found."

    response = JsonResponse(data={"error": message, "status_code": 404})
    response.status_code = 404
    return response


def error_400(request, exception):
    message = "Bad request."

    response = JsonResponse(data={"error": message, "status_code": 400})
    response.status_code = 400
    return response


def error_500(request):
    message = "Server error."

    response = JsonResponse(data={"error": message, "status_code": 500})
    response.status_code = 500
    return response

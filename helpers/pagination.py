from rest_framework import pagination


class MediaPageNumberPagination(pagination.PageNumberPagination):
    page_size = 35
    page_size_query_param = "count"
    max_page_size = 40
    page_query_param = "page"


class CustomPageNumberPagination(pagination.PageNumberPagination):
    page_size = 20
    page_size_query_param = "count"
    max_page_size = 30
    page_query_param = "page"
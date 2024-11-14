# from django.utils.deprecation import MiddlewareMixin

# import logging

# # Создание логгера для middleware
# MIDDLEWARE_LOGGER = logging.getLogger('middleware')
# class SessionLoggingMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         # Логирование данных сессии
#         MIDDLEWARE_LOGGER.debug(f"Session data: {request.session.items()}")
        
#         # Вызываем следующий middleware
#         response = self.get_response(request)
#         return response
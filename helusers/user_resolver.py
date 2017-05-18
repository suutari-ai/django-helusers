from .jwt import UserHandler


def get_or_create_user(request, payload):
    return UserHandler().get_or_create_user(payload)

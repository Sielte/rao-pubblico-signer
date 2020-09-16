from enum import Enum


class StatusCode(Enum):
    OK = 200
    ERROR = -1
    BAD_REQUEST = 400
    NOT_FOUND = 404
    UNAUTHORIZED = 401
    USER_DISABLED = -5


class RoleTag(Enum):
    ADMIN = 'ADMIN'
    OPERATOR = 'OPERATOR'

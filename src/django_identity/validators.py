import re

from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator, validate_email
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _


@deconstructible
class UnicodeUsernameValidator(RegexValidator):
    regex = r"r[\w.@+-]+\Z"
    # regex = r"^[\w@!\#\$%\&'\*\+\-/\\=\?\^`\{\|\}\~.]+\Z"
    message = _(
        "Enter a valid username. The username can be an email address "
        "or may contain letters, numbers, and ./@/+/-/_ characters."
    )
    flags = re.UNICODE, re.IGNORECASE

    def __call__(self, value):
        """
        Attempt to validate username as email address, then call
        username validator if email validation fails.
        """
        try:
            validate_email(value)
        except ValidationError:
            super().__call__(value)

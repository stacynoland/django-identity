from django.core import validators
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _


@deconstructible
class UnicodeUsernameValidator(validators.RegexValidator):
    regex = r"^[\w@!\#\$%\&'\*\+\-/\\=\?\^`\{\|\}\~.]+\Z"
    message = _(
        "Enter a valid username. The username can be an email address."
    )
    flags = 0

from uuid import uuid4 as uuid

from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin)
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .validators import UnicodeUsernameValidator


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user_obj(self, username, email, password, **extra_fields):
        if email:
            try:
                validate_email(email)
            except ValidationError:
                raise
        elif username:
            try:
                validate_email(username)
                email = username
            except ValidationError:
                raise
        else:
            raise ValueError("A valid email or username must be provided.")
        # TODO: Check if email already exists or needs to be verified
        user = self.model(username=username, **extra_fields)
        # TODO: Save email as primary for user after User model created
        user.password = make_password(password)
        return user

    def _create_user(self, username, email, password, **extra_fields):
        user = self._create_user_obj(username, email, password, **extra_fields)
        user.save(using=self._db)
        return user

    def create_user(self, username, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)

        if extra_fields.get('is_superuser') is True and \
            extra_fields.get('is_staff') is not True:
                raise ValueError("Superuser must have is_staff=True.")

        return self._create_user(username, email, password, **extra_fields)

    create_user.alters_data = True


class User(AbstractBaseUser, PermissionsMixin):

    username_validator = UnicodeUsernameValidator()

    id = models.UUIDField(
        primary_key=True,
        default=uuid,
        editable=False,
    )
    username = models.CharField(
        _("username"),
        max_length=254,
        unique=True,
        help_text=_("Required. 254 characters or less. May be an email address."),
        validators=[username_validator],
        error_messages={
            'unique': _("Please try again.")
        },
    )
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates if user can login to the admin site."),
    )
    is_active = models.BooleanField(
        _("active status"),
        default=False,
        help_text=_(
            "Designates whether user should be treated as active. "
            "Deselect instead of deleting accounts."
        )
    )
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now)

    objects = UserManager()

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")
        indexes = [models.Index(fields=['username'])]

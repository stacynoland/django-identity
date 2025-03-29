from uuid import uuid4 as uuid

from django.apps import apps
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin)
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user_obj(self, username, email, password, **extra_fields):
        if email:
            try:
                validate_email(email)
            except ValidationError as e:
                raise ValueError(f"Invalid email address: {email}.") from e
        elif username:
            try:
                validate_email(username)
                email = username
            except ValidationError as e:
                raise ValueError("Username must be a valid email or \
                                 an email must be provided.") from e
        else:
            raise TypeError("A valid email must be provided or username must be an email.")
        EmailModel = apps.get_model('django_identity', 'Email')
        normalized_email = EmailModel.normalize_full_email(email)
        if EmailModel.objects.filter(normalized_email=normalized_email).exists():
            raise ValueError("Email already exists.")
        user = self.model(username=username, **extra_fields)
        EmailModel.objects.create(
            user=user,
            email=email,
            normalized_email=normalized_email,
            is_primary=True,
        )
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
        # validators=[username_validator],
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

    @property
    def email(self):
        return self.get_primary_email()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")
        indexes = [models.Index(fields=['username'])]

    def get_primary_email(self):
        """Get primary email address for user."""
        try:
            return self.emails.get(is_primary=True).email
        except Email.DoesNotExist:
            raise
        except Email.MultipleObjectsReturned:
            raise


class Email(models.Model):

    id = models.UUIDField(
        primary_key=True,
        default=uuid,
        editable=False,
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='emails'
    )
    is_verified = models.BooleanField(
        _("email verified"),
        default=False,
        help_text=_("Designates email address has been verified."),
    )
    is_primary = models.BooleanField(
        _("primary email"),
        default=True,
        help_text=_("Designates email address is primary for user."),
    )
    _email = models.EmailField(
        _("email address"),
        unique=True,
        db_column='email',
        help_text=_(
            "Required. Must be a valid email address."
        ),
        error_messages={
            'unique': _("Please check your email for a verification link.")
        },
    )
    _normalized_email = models.EmailField(
        _("normalized email address"),
        unique=True,
        db_column='normalized_email',
        help_text=_(
            "Required. Must be a valid email address."
        ),
        error_messages={
            'unique': _("Please check your email for a verification link.")
        },
    )

    class Meta:
        verbose_name = _("email")
        verbose_name_plural = _("emails")
        indexes = [models.Index(fields=['email'])]

    def save(self, *args, **kwargs):
        if self.is_primary is True:
            if self.pk:
                self.objects.filter(user=self.user).exclude(pk=self.pk)\
                    .update(is_primary=False)
            else:
                self.objects.filter(user=self.user).update(is_primary=False)
        return super().save(*args, **kwargs)

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value):
        self._email = self.normalize_domain(value)

    @property
    def normalized_email(self):
        return self._normalized_email

    @normalized_email.setter
    def email(self, value):
        self._normalized_email = self.normalize_full_email(value)

    @classmethod
    def normalize_domain(cls, email):
        """Normalize domain part by lowercasing it."""
        email = email or ""
        if not isinstance(email, str):
            raise ValueError(f"value must be a string (type str): \
                             {type(email)} not supported")
        try:
            prefix, domain = email.strip().rsplit("@", 1)
        except ValueError:
            raise
        else:
            email = prefix + "@" + domain.lower()
        return email

    @classmethod
    def normalize_full_email(cls, email):
        """Normalize email address by lowercasing it."""
        email = email or ""
        if not isinstance(email, str):
            raise ValueError(f"value must be a string (type str): \
                             {type(email)} not supported")
        email = email.strip().lower()
        return email

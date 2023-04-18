from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from phonenumber_field.modelfields import PhoneNumberField
from django.dispatch import receiver
from django.urls import reverse
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import send_mail, EmailMultiAlternatives
from task_manager.settings import DEFAULT_FROM_EMAIL


@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):
    """
        Handles password reset tokens. Sends an email to the user when a token is created.
        """
    context = {
        'current_user': reset_password_token.user,
        'first_name': reset_password_token.user.first_name,
        'email': reset_password_token.user.email,
        'reset_password_url': f"{instance.request.build_absolute_uri(reverse('password_reset:reset-password-confirm'))}?token={reset_password_token.key}"
    }

    email_html_message = render_to_string('reset_password.html', context)

    subject = "Password Reset for Task Manager Account"
    from_email = DEFAULT_FROM_EMAIL
    to_email = reset_password_token.user.email

    msg = EmailMultiAlternatives(subject, email_html_message, from_email, [to_email])
    # msg.attach_alternative(email_html_message, "text/html")
    msg.send()


class CustomUserManager(BaseUserManager):
    """
    Custom user manager that uses email as the unique identifier for authentication.
    """

    def create_user(self, email, password=None, **extra_fields):
        """
        Creates and saves a new user with the given email and password.
        """
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates and saves a new superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser should have is_staff as True'))

        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser should have is_superuser as True'))

        if extra_fields.get('is_active') is not True:
            raise ValueError(_('Superuser should have is_active as True'))

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model with email field as the unique identifier for authentication.
    """
    username = None
    email = models.EmailField(_('email address'), unique=True, blank=False, null=False)
    first_name = models.CharField(_('first name'), max_length=30, blank=False, null=False)
    last_name = models.CharField(_('last name'), max_length=30, blank=False, null=False)
    password = models.CharField(_('password'), blank=False, null=False, max_length=16)
    phone_number = PhoneNumberField(null=False, unique=True)
    is_active = models.BooleanField(_('active'), default=False)
    is_staff = models.BooleanField(_('staff status'), default=False)
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    # New fields for email verification
    email_verified = models.BooleanField(_('email verified'), default=False,
                                         help_text=_('Designates whether the user has verified their email.'))

    objects = CustomUserManager()

    # Required for authentication using Django's built-in permissions
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email

    def has_email_verified(self):
        """
        Returns True if the user's email has been verified, False otherwise.
        """
        return self.email_verified

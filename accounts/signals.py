from django.contrib.auth import get_user_model
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.urls import reverse
from django.conf import settings
from rest_framework.authtoken.models import Token

User = get_user_model()


@receiver(post_save, sender=User, dispatch_uid="unique_identifier")
def send_confirmation_email(sender, instance, created, **kwargs):
    if created:
        try:
            subject = 'Confirm Your Email Address'
            message = render_to_string('email_confirmation.html', {
                'user': instance,
                'domain': '127.0.0.1:7000',
                'uid': urlsafe_base64_encode(force_bytes(instance.pk)),
                'token': default_token_generator.make_token(instance),
            })
            from_email = settings.EMAIL_HOST_USER
            print(from_email)
            to_email = instance.email
            send_mail(subject, message, from_email, [to_email], fail_silently=False)
            print('sent')
        except Exception as e:
            print(f'Error sending confirmation email to {e}')


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
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = reset_password_token.user.email

    msg = EmailMultiAlternatives(subject, email_html_message, from_email, [to_email])
    # msg.attach_alternative(email_html_message, "text/html")
    msg.send()


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)

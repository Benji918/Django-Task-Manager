from django.contrib.auth import get_user_model
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.template.loader import render_to_string
from django.utils.encoding import smart_bytes
from django.utils.http import urlsafe_base64_encode
from django.urls import reverse
from django.conf import settings

User = get_user_model()


@receiver(post_save, sender=User, dispatch_uid="unique_identifier")
def send_confirmation_email(sender, instance, created, **kwargs):
    if created:
        print('hello')
        try:
            subject = 'Confirm Your Email Address'
            message = render_to_string('templates/email_confirmation.html', {
                'user': instance,
                'domain': 'localhost:8000',
                'uid': urlsafe_base64_encode(smart_bytes(instance.pk)),
                'token': default_token_generator.make_token(instance),
            })
            from_email = settings.EMAIL_HOST_USER
            print(from_email)
            to_email = instance.email
            send_mail(subject, message, from_email, [to_email], fail_silently=False)
            print('sent')
        except Exception as e:
            print(f'Error sending confirmation email: {e}')



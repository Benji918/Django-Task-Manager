from django.urls import path, include
from .views import RegisterView, ConfirmEmailView

app_name = 'accounts'

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path("reset_password/", include("django_rest_passwordreset.urls", namespace="password_reset")),
    path('confirm_email/<uidb64>/<str:token>/', ConfirmEmailView.as_view(), name='confirm_email'),
]


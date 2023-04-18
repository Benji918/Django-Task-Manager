from django.urls import path, include
from .views import RegisterView, ConfirmEmailView, ChangePasswordView, LoginView

app_name = 'accounts'

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('change_password/', ChangePasswordView.as_view(), name='change-password'),
    path('confirm_email/<uidb64>/<str:token>/', ConfirmEmailView.as_view(), name='confirm_email'),
]


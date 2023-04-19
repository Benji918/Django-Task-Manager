from django.contrib.auth import get_user_model, authenticate
from django.utils.encoding import smart_str, force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import generics, permissions, status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from drf_yasg.utils import swagger_auto_schema
from .serializers import UserSerializer, ChangePasswordSerializer, LoginSerializer
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import login

User = get_user_model()


# Create your views here.
class RegisterView(generics.GenericAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny, ]

    @swagger_auto_schema(operation_summary="Endpoint for a User Registration")
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'status': 'success',
            'code': status.HTTP_201_CREATED,
            "user": UserSerializer(user, context=self.get_serializer_context()).data,
            "token": token.key,
            "message": "User account created successfully"
        })


class LoginView(generics.GenericAPIView):
    """
        API view to handle user login.
        """
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny, ]

    @swagger_auto_schema(operation_summary="Endpoint for a user Login")
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request, username=email, password=password)
        if user is not None:
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'status': 'success',
                'code': status.HTTP_200_OK,
                'user': LoginSerializer(user, context=self.get_serializer_context()).data,
                'token': token.key,
                "message": "Logged in successfully"

            })
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(generics.GenericAPIView):
    """
    API view to handle user logout.
    """
    permission_classes = [permissions.IsAuthenticated, ]

    @swagger_auto_schema(operation_summary="Endpoint for a user Logout")
    def post(self, request):
        try:
            # delete the user token
            token = Token.objects.get(user=request.user)
            token.delete()
        except Token.DoesNotExist:
            return Response({"error": "Token error occurred!"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            'status': 'success',
            'code': status.HTTP_200_OK,
            'message': 'Logged out successfully'
        })


class ConfirmEmailView(generics.GenericAPIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request, token, uidb64):
        # find the user by the token
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid user ID"}, status=status.HTTP_400_BAD_REQUEST)

        if user and default_token_generator.check_token(user, token):
            # update the email_verified  and email_active flag
            user.email_verified = True
            user.is_active = True
            user.save()
            return Response({"message": "Email confirmation successful"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated]
    http_method_names = ['get', 'post', 'put']
    model = User


    @swagger_auto_schema(operation_summary="Endpoint for Change User password")
    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("confirm_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

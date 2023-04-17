from django.contrib.auth import get_user_model
from django.utils.encoding import smart_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from knox.models import AuthToken
from drf_yasg.utils import swagger_auto_schema
from .serializers import UserSerializer
from django.contrib.auth.tokens import default_token_generator

User = get_user_model()


# Create your views here.
class RegisterView(generics.GenericAPIView):
    serializer_class = UserSerializer

    @swagger_auto_schema(operation_summary="Endpoint for a User Registration")
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
           'status': 'success',
           'code': status.HTTP_201_CREATED,
           "user": UserSerializer(user, context=self.get_serializer_context()).data,
           "token":  AuthToken.objects.create(user)[1],
           "message": "User account created successfully"
        })


class ConfirmEmailView(generics.GenericAPIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request, token, uidb64=None):
        # find the user by the token
        try:
            uid = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid user ID"}, status=status.HTTP_400_BAD_REQUEST)


        if default_token_generator.check_token(user, token):
            # update the email_verified flag
            user.email_verified = True
            user.is_active = True
            user.save()
            return Response({"message": "Email confirmation successful"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)


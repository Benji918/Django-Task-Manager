from django.contrib.auth import get_user_model
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from knox.models import AuthToken
from drf_yasg.utils import swagger_auto_schema
from .serializers import UserSerializer

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


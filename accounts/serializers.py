from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers
from .validators import validate_strong_password
from rest_framework.exceptions import AuthenticationFailed

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True,
                                     validators=[validate_strong_password])
    confirm_password = serializers.CharField(style={'input_type': 'password'}, write_only=True,
                                             validators=[validate_strong_password])

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'phone_number', 'password', 'confirm_password')
        extra_kwargs = {
            'email': {'required': True},
            'confirm_password': {'required': True},
            'password': {'write_only': True, 'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True}
        }

    def validate(self, data):
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        if password != confirm_password:
            raise serializers.ValidationError('Passwords must match')
        return data

    def create(self, validated_data):
        user = User.objects.create(
            first_name=validated_data.get('first_name'),
            last_name=validated_data.get('last_name'),
            email=validated_data.get('email'),
            phone_number=validated_data.get('phone_number'),
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('is_superuser', 'is_staff', 'is_active', "date_joined", 'last_login')


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = get_user_model().objects.filter(email=email).first()
            if user:
                if not user.check_password(password):
                    raise serializers.ValidationError('Invalid password')
            else:
                raise serializers.ValidationError('User not found. Invalid credentials!')
        else:
            raise serializers.ValidationError('Must include "email" and "password".')
        attrs['user'] = user
        return attrs


class ChangePasswordSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_strong_password])
    confirm_password = serializers.CharField(required=True, validators=[validate_strong_password])

    def validate(self, data):
        """
        Check that new_password and confirm_password match
        """
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("The new password do not match.")
        return data

    class Meta:
        model = User
        fields = ['old_password', 'new_password', 'confirm_password']
        extra_kwargs = {'password': {'write_only': True}}

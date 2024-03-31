from rest_framework import serializers
from .models import User
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.core.mail import send_mail
from django.utils.translation import gettext_lazy as _


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'first_name',
                  'last_name', 'profile_image', 'cover_image']

    def validate_email(self, value):
        try:
            validate_email(value)
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        return value

    def validate_password(self, value):
        # Add your password validation logic here
        if len(value) < 8:
            raise serializers.ValidationError(
                "Password must be at least 8 characters long")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        self.send_verification_email(user)
        return user

    def send_verification_email(self, user):
        token = RefreshToken.for_user(user).access_token
        verification_url = f"{
            settings.SITE_URL}/verify-email/{user.pk}/{token}/"
        send_mail(
            _('Verify your email address'),
            f'Click the link below to verify your email address:\n\n{
                verification_url}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

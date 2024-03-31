from rest_framework_simplejwt.views import TokenObtainPairView
from django.conf import settings
from django.http import JsonResponse
from .models import User
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .serializer import UserSerializer
from rest_framework_simplejwt.views import TokenRefreshView


class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')
            first_name = serializer.validated_data.get('first_name')
            last_name = serializer.validated_data.get('last_name')
            email = serializer.validated_data.get('email')
            profile_img = serializer.validated_data.get('profile_img')
            address_id = serializer.validated_data.get('address_id')

            # Check if the user already exists
            user_exists = User.objects.filter(username=username).exists()

            if user_exists:
                # Login logic
                response = super().post(request, *args, **kwargs)
                refresh_token = response.data['refresh']
                access_token = response.data['access']
            else:
                # Sign-up logic
                # Create a new user
                user = User.objects.create_user(
                    username=username, password=password, first_name=first_name, last_name=last_name, email=email)
                user.profile_img = profile_img
                user.address_id = address_id
                user.save()

                # Generate tokens for the new user
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)

            # Set cookies for the tokens
            response = JsonResponse({
                'message': 'Authentication successful'
            })
            response.set_cookie('access_token', access_token,
                                max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(), httponly=True, samesite='Lax')
            if user_exists:
                response.set_cookie('refresh_token', refresh_token,
                                    max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds(), httponly=True, samesite='Lax')
            else:
                response.set_cookie('refresh_token', str(refresh),
                                    max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds(), httponly=True, samesite='Lax')

            return response

        return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            refresh_token = serializer.validated_data.get('refresh')
            response = super().post(request, *args, **kwargs)
            access_token = response.data.get('access')

            # Set cookies for the tokens
            response.set_cookie('access_token', access_token,
                                max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(), httponly=True, samesite='Lax')
            response.set_cookie('refresh_token', refresh_token,
                                max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds(), httponly=True, samesite='Lax')

            return response

        return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

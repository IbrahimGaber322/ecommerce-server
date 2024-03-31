from rest_framework_simplejwt.views import TokenObtainPairView
from django.conf import settings
from django.http import JsonResponse
from .models import User
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
import uuid


class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        email = request.data.get('email')
        profile_img = request.data.get('profile_img')
        address_id = request.data.get('address_id')

        if username and password:
            # Check if the user already exists
            if User.objects.filter(username=username).exists():
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

            # Generate a unique identifier to use as the cookie value
            access_token_uuid = str(uuid.uuid4())
            refresh_token_uuid = str(uuid.uuid4())

            # Store the tokens in a dictionary with the identifier as the key
            token_dict = {
                access_token_uuid: access_token,
                refresh_token_uuid: str(refresh)
            }

            response = JsonResponse({
                'message': 'Authentication successful'
            })

            # Set cookies for the unique identifiers
            response.set_cookie('access_token', access_token_uuid,
                                max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(), httponly=True, samesite='Lax')
            response.set_cookie('refresh_token', refresh_token_uuid,
                                max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds(), httponly=True, samesite='Lax')

            # Store the tokens in the session (or another storage mechanism) on the server side
            request.session['tokens'] = token_dict

            return response

        return JsonResponse({'error': 'Username and password are required'}, status=status.HTTP_400_BAD_REQUEST)

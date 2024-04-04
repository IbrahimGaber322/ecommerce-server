from rest_framework import serializers

from .models import User


class SignUpSerializer(serializers.ModelSerializer):
    first_name = serializers.RegexField(
        "^[a-zA-Z]+$",
        min_length=3,
        max_length=15,
        allow_blank=False,
        required=True,
        error_messages={
            "invalid": "Only lower or upper case letters are allowed"},
    )

    last_name = serializers.RegexField(
        "^[a-zA-Z]+$",
        min_length=3,
        max_length=15,
        allow_blank=False,
        required=True,
        error_messages={
            "invalid": "Only lower or upper case letters are allowed"},
    )

    email = serializers.EmailField(required=True)

    password = serializers.RegexField(
        "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$",
        error_messages={
            "invalid": " Minimum eight characters, at least one upper case English letter, one lower case English letter, one number and one special character "
        },
        required=True,
    )

    profile_image = serializers.ImageField(required=False)
    cover_image = serializers.ImageField(required=False)

    def validate_email(self, value):
        """
        Check if the email already exists in the user database.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name",
                  "email", "password", "profile_image", "cover_image"]
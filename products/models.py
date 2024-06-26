from cloudinary.models import CloudinaryField
from django.core.validators import MinValueValidator
from django.db import models

from category.models import Category


class Product(models.Model):
    name = models.CharField(max_length=30)
    description = models.CharField(max_length=100, blank=True)
    price = models.DecimalField(
        validators=[MinValueValidator(0)], max_digits=12, decimal_places=3
    )
    stock = models.PositiveIntegerField()
    category = models.ForeignKey(Category, on_delete=models.RESTRICT)
    stripe_id = models.CharField(max_length=1000, blank=True, null=True)

    def __str__(self):
        return self.name


class Image(models.Model):
    image_url = CloudinaryField("image")
    product = models.ForeignKey(Product, on_delete=models.RESTRICT)

    def __str__(self):
        return str(self.product)

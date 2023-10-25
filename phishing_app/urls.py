from django.urls import path
from .views import index, ClassifyURLView 

urlpatterns = [
    path('', index, name='index'),  # Map the root URL to the index view

    # Use class-based views with their `as_view` method
    path('classify/', ClassifyURLView.as_view(), name='classify_url'),
]

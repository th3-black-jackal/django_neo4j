"""Minimal settings used only to run the threatgraph tests."""
SECRET_KEY = "test-only"
DEBUG = True
ALLOWED_HOSTS = ["*"]
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.contenttypes", "rest_framework",
                  "rest_framework.authtoken", "threatgraph"]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
ROOT_URLCONF = "demo.urls"
"""REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.TokenAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}"""
NEO4J = {"URI": "bolt://localhost:7687", "USER": "neo4j", "PASSWORD": "ChangeMe123", "DATABASE": "neo4j"}
USE_TZ = True

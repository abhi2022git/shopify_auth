from django.http.response import HttpResponseRedirect
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
import binascii
import os
import requests
import time
from account.serializers import ShopifyOauthSerializer, ShopifyUserCreationSerializer
from account.utils.constants import ShopifyOauth
from account.utils.oauth_client import ShopifyOauthClient


class ShopifyOauthRedirectAPIView(GenericAPIView):
    """Redirects to Shopify to confirm permissions
    """
    permission_classes = [AllowAny]
    serializer_class = ShopifyOauthSerializer

    def get(self, request):
            state = binascii.b2a_hex(os.urandom(15)).decode("utf-8")
            redirect_uri = "https://cc5d-223-178-212-160.in.ngrok.io/auth/shopify/callback"
            scopes = ['read_products', 'read_orders']

            newSession = shopify.Session(shop_url, api_version)
            auth_url = newSession.create_permission_url(scopes, redirect_uri, state)
            return HttpResponseRedirect(auth_url)


class ShopifyUserCreationAPIView(GenericAPIView):
    """Creates new user for Shopify Public App
    """
    permission_classes = [AllowAny]
    serializer_class = ShopifyOauthSerializer

    def get(self, request):
        serializer = self.get_serializer(data=request.query_params)
        if serializer.is_valid(raise_exception=True):
            shop_name = serializer.validated_data['shop']
            oauth_client = ShopifyOauthClient(shop_name)
            token = oauth_client.get_access_token(
                client_id=ShopifyOauth.API_KEY,
                client_secret=ShopifyOauth.SECRET_KEY,
                code=serializer.validated_data['code']
            )
            email, owner = oauth_client.get_shop_details()
            serializer = ShopifyUserCreationSerializer(
                data={
                    "email": email,
                    "full_name": owner,
                    "shop_name": shop_name,
                    'token': token,
                    'state': request.query_params.get("state")
                }
            )
            if serializer.is_valid(raise_exception=True):
                user = serializer.create(validated_data=serializer.validated_data)
                bridge_url = f"https://{shop_name}/admin/apps/check"
                return HttpResponseRedirect(redirect_to=bridge_url)

        return Response({"message": "Authentication failed"})
from django.utils.translation import ugettext as _
from django.contrib.auth import get_user_model
from django.conf import settings
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.settings import api_settings
from rest_framework import exceptions
import random

User = get_user_model()


def patch_jwt_settings():
    """Patch rest_framework_jwt authentication settings from allauth"""
    defaults = api_settings.defaults
    defaults['JWT_PAYLOAD_GET_USER_ID_HANDLER'] = 'helusers.jwt.get_user_id_from_payload_handler'

    if 'allauth.socialaccount' not in settings.INSTALLED_APPS:
        return

    from allauth.socialaccount.models import SocialApp
    try:
        app = SocialApp.objects.get(provider='helsinki')
    except SocialApp.DoesNotExist:
        return

    defaults['JWT_SECRET_KEY'] = app.secret
    defaults['JWT_AUDIENCE'] = app.client_id

# Disable automatic settings patching for now because it breaks Travis.
# patch_jwt_settings()


class JWTAuthentication(JSONWebTokenAuthentication):

    def populate_user(self, user, data):
        exclude_fields = ['is_staff', 'password', 'is_superuser', 'id']
        user_fields = [f.name for f in user._meta.fields if f.name not in exclude_fields]
        changed = False
        for field in user_fields:
            if field in data:
                val = data[field]
                if getattr(user, field) != val:
                    setattr(user, field, val)
                    changed = True

        # Make sure there are no duplicate usernames
        tries = 0
        while User.objects.filter(username=user.username).exclude(uuid=user.uuid).exists():
            user.username = "%s-%d" % (user.username, tries + 1)
            changed = True

        return changed

    def authenticate_credentials(self, payload):
        user_id = payload.get('sub')
        if not user_id:
            msg = _('Invalid payload.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            user = User.objects.get(uuid=user_id)
        except User.DoesNotExist:
            user = User(uuid=user_id)
            user.set_unusable_password()

        changed = self.populate_user(user, payload)
        if changed:
            user.save()

        ad_groups = payload.get('ad_groups', None)
        # Only update AD groups if it's a list of non-empty strings
        if isinstance(ad_groups, list) and \
                all([isinstance(x, str) and len(x) for x in ad_groups]):
            user.update_ad_groups(ad_groups)

        # If allauth.socialaccount is installed, create the SocialAcount
        # that corresponds to this user. Otherwise logins through
        # allauth will not work for the user later on.
        if 'allauth.socialaccount' in settings.INSTALLED_APPS:
            from allauth.socialaccount.models import SocialAccount, EmailAddress

            args = {'provider': 'helsinki', 'uid': user_id}
            try:
                account = SocialAccount.objects.get(**args)
                assert account.user_id == user.id
            except SocialAccount.DoesNotExist:
                account = SocialAccount(**args)
                account.extra_data = payload
                account.user = user
                account.save()

                try:
                    email = EmailAddress.objects.get(email__iexact=user.email)
                    assert email.user == user
                except EmailAddress.DoesNotExist:
                    email = EmailAddress(email=user.email.lower(), primary=True, user=user,
                                         verified=True)
                    email.save()

        if not user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.AuthenticationFailed(msg)
        return user

# =========================================================
# Code copy pasted with slight modifications from apikey.py

import jwt
from jwkest import jws, jwk


def decode_id_token(id_token):
    jwt = jws.JWSig().unpack(id_token)
    kid = jwt.headers['kid']
    key = get_key(kid)
    return jws.JWS().verify_compact(id_token, keys=[key], sigalg='RS256')


key_cache = {}


def get_key(kid, jwks_url=None):
    key = key_cache.get(kid)
    if key is None:
        if jwks_url is None:
            # TODO: Use oidc discovery and store to settings
            jwks_url = 'http://localhost:8000/openid/jwks'
        for key in get_keys(jwks_url):
            if key.kid not in key_cache:
                key_cache[key.kid] = key
        key = key_cache.get(kid)
        if key is None:
            raise LookupError('Unknown key: kid=%r' % (kid,))
    return key


def get_keys(jwks_url):
    import requests

    check_url_is_secure(jwks_url)
    data = requests.get(jwks_url).json()
    return [
        jwk.key_from_jwk_dict(key_data, private=False)
        for key_data in data.get('keys', [])]


def check_url_is_secure(url):
    import urllib.parse

    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme not in ('https', 'http'):
        raise Exception('URL scheme is not HTTPS or HTTP: %r' % (url,))  # TODO: exception type
    is_localhost = parsed_url.netloc.split(':')[0] == 'localhost'
    if parsed_url.scheme == 'http' and not is_localhost:
        raise Exception(
            'HTTP scheme is allowed only for localhost URLs: %r' % (url,))  # TODO: exception type


class OIDCAuthentication(JWTAuthentication):

    # Reson I had to override this method was that the super uses
    # jwt_decode_handler which is only configurable via settings.JWT_DECODE_HANDLER
    # We could use that to configure the decoder, but if we need to support
    # two different decoders for Oauth2 and OIDC simultaniously then the
    # configuration is not enough and we need to override this method or do
    # something similar..
    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication.  Otherwise returns `None`.
        """
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None

        try:
            # Replaced original `jwt_decode_handler` with `decode_id_token`
            payload = decode_id_token(jwt_value)
        except jwt.ExpiredSignature:
            msg = _('Signature has expired.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.DecodeError:
            msg = _('Error decoding signature.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed()

        user = self.authenticate_credentials(payload)

        return (user, jwt_value)

    # Had to override this method for the same reasons as `authenticate`
    def get_jwt_value(self, request):
        # Put these imports there just temporarily..
        from rest_framework.authentication import get_authorization_header
        from django.utils.encoding import smart_text

        auth = get_authorization_header(request).split()
        # Original
        # api_settings.JWT_AUTH_HEADER_PREFIX.lower()
        # Fixed prefix assignment since the setting configuration doesn't
        # support having two separate prefixes simultaniously.
        auth_header_prefix = 'Bearer'

        if not auth or smart_text(auth[0]) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid Authorization header. Credentials string '
                    'should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        return auth[1]


def get_user_id_from_payload_handler(payload):
    return payload.get('sub')

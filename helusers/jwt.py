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
        self.update_user_groups(user, payload)

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

    def update_user_groups(self, user, payload):
        permissions = payload.get(JWT_PERMISSION_FIELD)

        if permissions is None:
            return None

        new_api_groups = set(
            API_GROUP_PREFIX + perm
            for perm in permissions
            if perm.split('.', 1)[0] == PERMISSION_PREFIX)
        api_group_map = dict(
            user.groups.filter(name__starstswith=API_GROUP_PREFIX)
            .values_list('name', 'pk'))
        current_api_groups = set(api_group_map)

        if new_api_groups == current_api_groups:
            return False

        for group_to_remove in (current_api_groups - new_api_groups):
            user.groups.remove(api_group_map[group_to_remove])

        for group_to_add in (new_api_groups - current_api_groups):
            groups = user.groups.model.objects
            (group, created) = groups.get_or_create(name=group_to_add)
            user.groups.add(group)

        return True


# =========================================================
# Code copy pasted with slight modifications from apikey.py

import jwkest
import jwt
import requests
import six
from jwkest import jws, jwk


class Error(Exception): pass  # noqa
class InvalidJwtError(Error): pass  # noqa
class KeyFetchFailedError(Error): pass  # noqa
class VerificationFailedError(Error): pass  # noqa
class ExpiredError(VerificationFailedError): pass  # noqa
class BadSignatureError(VerificationFailedError): pass  # noqa
class InvalidIssuerError(Error): pass  # noqa
class InvalidAudienceError(Error): pass  # noqa


API_GROUP_PREFIX = 'api.'
PERMISSION_PREFIX = 'kerrokantasi'
JWT_PERMISSION_FIELD = 'https://api.hel.fi/auth'
OIDC_ISSUER = 'http://localhost:8000/openid'  # TODO: Move to settings
OIDC_CLIENT_ID = 'https://api.hel.fi/auth/kerrokantasi'


def verify_and_decode_id_token(id_token):
    """
    Verify an ID token and decode its contents.

    The verification checks the signature against the public key of the
    issuer and then checks that the issuer (iss) and audience (aud) of
    the ID token are correct.

    :type id_token: bytes
    :param id_token: The ID token, encoded in JWT format
    :rtype: dict
    :return: Decoded payload of the ID token
    :raises Error: if verification fails
    """
    parts = id_token.split(b'.')
    import base64, json
    decoded_parts = [
        json.loads(base64.b64decode(part + b'====').decode('utf-8'))
        for part in parts[0:2]]
    #decoded_parts[0]['kid'] = 'moi'
    parts = [
        base64.b64encode(json.dumps(decoded_part).encode('utf-8'))
        for decoded_part in decoded_parts] + parts[2:]
    id_token = b'.'.join(parts)

    key = get_key_from_id_token(id_token)

    # Verify the ID token signature and extract the payload
    try:
        payload = jws.JWS().verify_compact(
            id_token, keys=[key], sigalg='RS256')
    except jwkest.Expired:
        raise ExpiredError('ID token has been expired')
    except jwkest.BadSignature:
        raise BadSignatureError('Signature of the ID token is invalid')
    except Exception as verify_error:
        six.raise_from(
            VerificationFailedError('ID token verification failed'),
            verify_error)

    # Check issuer
    if payload['iss'] != OIDC_ISSUER:
        raise InvalidIssuerError(
            'Invalid issuer in ID token: {}'.format(payload['iss']))

    # Check audience
    aud = payload['aud']
    audiences = aud if isinstance(aud, list) else [aud]
    if OIDC_CLIENT_ID not in audiences:
        raise InvalidAudienceError(
            'ID token is not for us, its audience = {!r}'.format(aud))

    return payload


key_cache = {}


def get_key_from_id_token(id_token):
    try:
        unpacked_jwt = jws.JWSig().unpack(id_token)
    except Exception as unpack_error:
        six.raise_from(
            InvalidJwtError('Not a valid JWT'), unpack_error)
    kid = unpacked_jwt.headers.get('kid')
    if not kid:
        raise InvalidJwtError('No key identifier (kid) in JWT.')
    try:
        return get_key(kid)
    except Exception as key_fetch_error:
        six.raise_from(
            KeyFetchFailedError(
                'Failed to fetch key {} from the OpenID Provider'.format(kid)),
            key_fetch_error)


def get_key(kid, issuer=None):
    key = key_cache.get(kid)
    if key is None:
        endpoints = discover_oidc_endpoints(issuer)
        jwks_url = endpoints['jwks_uri']
        for key in get_keys(jwks_url):
            if key.kid not in key_cache:
                key_cache[key.kid] = key
        key = key_cache.get(kid)
        if key is None:
            raise LookupError('Unknown key: kid=%r' % (kid,))
    return key


def discover_oidc_endpoints(issuer=None):
    if issuer is None:
        issuer = OIDC_ISSUER  # TODO: Use settings
    response = requests.get(issuer + '/.well-known/openid-configuration')
    response.raise_for_status()
    import pprint; pprint.pprint(response.json())
    return response.json()


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
            payload = verify_and_decode_id_token(jwt_value)
        except Error as error:
            #raise
            msg = str(error) # TODO: Translated messages?
            raise exceptions.AuthenticationFailed(msg)

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

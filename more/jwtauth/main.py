from sys import version_info
import datetime

import morepath
from morepath.security import IdentityPolicy
from morepath import (settings, Identity, NO_IDENTITY)

import jwt


class JwtApp(morepath.App):
    pass


@JwtApp.identity_policy()
def get_identity_policy():
    return JWTIdentityPolicy()


@JwtApp.setting_section(section="jwtauth")
def get_jwtauth_settings():
    """The following settings are available:

        * master_secret:  A secret known only by the server, used for the default HMAC (HS*) algorithm.

        * private_key:  An RSA or an Elliptic Curve private_key used for the RSA (RS*) or EC (EC*) algorithms.
        * private_key_file: A file holding an RSA encoded (PEM/DER) or an Elliptic Curve private_key.

        * public_key:  An RSA or an Elliptic Curve public_key used for the RSA (RS*) or EC (EC*) algorithms.
        * public_key_file: A file holding an RSA encoded (PEM/DER) or an Elliptic Curve public_key.

        * algorithm:  The algorithm used to sign the key (defaults to HS256).

        * expiration_delta: Time delta from now until the token will expire.
                            Default is 6 hours, set to None to disable.

        * leeway:  The leeway, which allows you to validate an expiration time which is in the past,
                   but not very far. To use as a datetime.timedelta. Defaults is None.

        * verify_expiration: Default is True. If you set it to False and expiration_delta is not None,
                             you should verify the "exp" claim by yourself and if it is expired you can either
                             refresh the token or you must reject it.

        * issuer: This is a string that will be checked against the iss claim of the token. You can use this e.g.
                  if you have several related apps with exclusive user audience.
                  Default is None (do not check iss on JWT).

        * auth_header_prefix: You can modify the Authorization header value prefix that is required to be sent together
                              with the token. The default value is JWT. Another common value used for tokens is Bearer.

        * userid_claim: The claim, which contains the user id. The default claim is 'sub'.

    The library takes either a master_secret or private_key/public_key pair.
    In the later case the algorithm must be an RS* or EC* version.
    """

    return {
        'master_secret': None,
        'private_key': None,
        'private_key_file': None,
        'public_key': None,
        'public_key_file': None,
        'algorithm': "HS256",
        'expiration_delta': datetime.timedelta(hours=6),
        'leeway': 0,
        'verify_expiration': True,
        'issuer': None,
        'auth_header_prefix': "JWT",
        'userid_claim': "sub"
    }


class JWTIdentityPolicy(IdentityPolicy):
    """Morepath Identity Policy implementing JWT Access Auth.

    This class provides an IdentityPolicy implementation based on
    signed requests, using the JSON Web Token Authentication standard.

    Reference: http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
    """

    def identify(self, request):
        """Establish what identity this user claims to have from request.

        :param request: Request to extract identity information from.
        :type request: :class:`morepath.Request`.
        :returns: :class:`morepath.security.Identity` instance or
          :attr:`morepath.security.NO_IDENTITY` if identity cannot
          be established.
        """
        settings_jwtauth = settings(lookup=request.lookup).jwtauth
        token = get_jwt(request, settings_jwtauth)
        if token is None:
            return NO_IDENTITY
        claims_set = decode_jwt(token, settings_jwtauth)
        if claims_set is None:
            return NO_IDENTITY
        userid = get_userid(claims_set, settings_jwtauth)
        if userid is None:
            return NO_IDENTITY
        extra_claims = get_extra_claims(claims_set, settings_jwtauth)
        if extra_claims is not None:
            return Identity(userid=userid, **extra_claims)
        else:
            return Identity(userid=userid)

    def remember(self, response, request, identity):
        """Remember identity on response.

        Implements ``morepath.remember_identity``, which is called
        from user login code.

        This is a no-op for this plugin; the client is supposed to remember
        its token and return it for all requests.

        :param response: response object on which to store identity.
        :type response: :class:`morepath.Response`
        :param request: request object.
        :type request: :class:`morepath.Request`
        :param identity: identity to remember.
        :type identity: :class:`morepath.security.Identity`

        """
        pass

    def forget(self, response, request):
        """Forget identity on response.

        Implements ``morepath.forget_identity``, which is called from
        user logout code.

        This simply issues a new WWW-Authenticate challenge, which should
        cause the client to forget any previously-provisioned credentials.

        :param response: response object on which to forget identity.
        :type response: :class:`morepath.Response`
        :param request: request object.
        :type request: :class:`morepath.Request`

        """
        response.headers.add('WWW-Authenticate', 'JWT realm="morepath"')


def decode_jwt(token, settings_jwtauth):
    """Decode a JWTAuth token into its claims set.

    This method decodes the given JWT to provide the claims set.  The JWT can
    fail if the token has expired (with appropriate leeway) or if the
    token won't validate due to the secret (key) being wrong.

    If private_key/public key is set then the public_key will be used to
    decode the key.
    The leeway, issuer and verify_expiration settings will be passed to jwt.decode.
    """
    key = settings_jwtauth.master_secret
    public_key = settings_jwtauth.public_key
    if settings_jwtauth.public_key_file is not None:
        with open(settings_jwtauth.public_key_file, 'r') as rsa_pub_file:
            public_key = rsa_pub_file.read()
    if public_key is not None:
        key = public_key
    if settings_jwtauth.leeway is not None:
        leeway = settings_jwtauth.leeway
    else:
        leeway = 0
    try:
        claims_set = jwt.decode(
            token,
            key,
            verify_expiration=settings_jwtauth.verify_expiration,
            leeway=leeway,
            issuer=settings_jwtauth.issuer
        )
    except (jwt.DecodeError, jwt.ExpiredSignature):
        return None
    return claims_set


def create_claims_set(userid, settings_jwtauth, extra_claims=None):
    """Create the claims set based on the userid of the claimed identity, the settings and the extra_claims dictionary.

    The userid will be stored in the registry.settings.jwtauth.userid_claim (default: "sub").
    If registry.settings.jwtauth.expiration_delta is set it will be added to the current time
    and stored in the "exp" claim.
    If registry.settings.jwtauth.issuer is set, it get stored in the "iss" claim.
    With the extra_claims dictionary you can provide additional claims. This can be registered claims like "nbf"
    (the datetime before which the token should not be processed) and/or claims containing extra info
    about the identity, which will be stored in the Identity object.
    """
    expiration_delta = settings_jwtauth.expiration_delta
    issuer = settings_jwtauth.issuer
    userid_claim = settings_jwtauth.userid_claim
    claims_set = {userid_claim: userid}
    if expiration_delta is not None:
        claims_set['exp'] = datetime.datetime.utcnow() + expiration_delta
    if issuer is not None:
        claims_set['iss'] = issuer
    if extra_claims is not None:
        claims_set.update(extra_claims)
    return claims_set


def encode_jwt(claims_set, settings_jwtauth):
    """Encode a JWT token based on the claims_set and the settings.

    If available, registry.settings.jwtauth.private_key is used as key.
    In this case the algorithm must be an RS* or EC* algorithm.
    If registry.settings.jwtauth.private_key is not set, registry.settings.jwtauth.master_secret is used.
    registry.settings.jwtauth.algorithm is used as algorithm.
    """
    key = settings_jwtauth.master_secret
    private_key = settings_jwtauth.private_key
    if settings_jwtauth.private_key_file is not None:
        with open(settings_jwtauth.private_key_file, 'r') as rsa_priv_file:
            private_key = rsa_priv_file.read()
    if private_key is not None:
        key = private_key
    algorithm = settings_jwtauth.algorithm
    token = jwt.encode(claims_set, key, algorithm)
    if version_info >= (3, 0, 0):
        token = token.decode(encoding='UTF-8')
    return token


def get_userid(claims_set, settings_jwtauth):
    """Extract the userid from a claims set.

    Returns userid or None if there is none.
    """
    userid_claim = settings_jwtauth.userid_claim
    if userid_claim in claims_set:
        userid = claims_set[userid_claim]
    else:
        return None
    return userid


def get_extra_claims(claims_set, settings_jwtauth):
    """Get claims holding extra identity info from the claims set.

    Returns a dictionary of extra claims or None if there are none.
    """
    userid_claim = settings_jwtauth.userid_claim
    reserved_claims = (userid_claim, "iss", "aud", "exp", "nbf", "iat", "jti")
    extra_claims = {}
    for claim in claims_set:
        if claim not in reserved_claims:
            extra_claims[claim] = claims_set[claim]
    if not extra_claims:
        return None
    return extra_claims


def get_jwt(request, settings_jwtauth):
    """Extract the JWT token from the authorisation header of the request.

     Returns the JWT token or None, if the token cannot be extracted.
    """
    auth_header_prefix = settings_jwtauth.auth_header_prefix
    try:
        authorization = request.authorization
    except ValueError:
        return None
    if authorization is None:
        return None
    authtype, token = authorization
    if authtype.lower() != auth_header_prefix.lower():
        return None
    if token is None:
        return None
    return token


def set_jwt_auth_header(request, userid, extra_claims=None):
    """Create a JWT token and return it as the Authorization field of the response header.

    This function can be called on response to a successful login request as a callback function
    after the view is processed using the morepath.Request.after() decorator.
    """
    settings_jwtauth = morepath.settings(lookup=request.lookup).jwtauth
    auth_header_prefix = settings_jwtauth.auth_header_prefix
    claims_set = create_claims_set(userid, settings_jwtauth, extra_claims)
    token = encode_jwt(claims_set, settings_jwtauth)
    return '%s %s' % (auth_header_prefix, token)


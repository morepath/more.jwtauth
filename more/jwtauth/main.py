"""Provides the JWTIdentityPolicy.

The following settings are available:

    * master_secret:  A secret known only by the server, used for the default HMAC (HS*) algorithm.

    * private_key:  An Elliptic Curve or an RSA private_key used for the EC (EC*) or RSA (PS*/RS*) algorithms.
    * private_key_file: A file holding an Elliptic Curve or an RSA encoded (PEM/DER) private_key.

    * public_key:  An Elliptic Curve or an RSA public_key used for the EC (EC*) or RSA (PS*/RS*) algorithms.
    * public_key_file: A file holding an Elliptic Curve or an RSA encoded (PEM/DER) public_key.

    * algorithm:  The algorithm used to sign the key (defaults to HS256).

    * expiration_delta: Time delta from now until the token will expire.
                        Default is 6 hours, set to None to disable.

    * leeway:  The leeway, which allows you to validate an expiration time which is in the past,
               but not very far. To use as a datetime.timedelta. Defaults is 0.

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
In the later case the algorithm must be an EC*, PS* or RS* version.
"""


import datetime
import sys

import jwt
from morepath import NO_IDENTITY, Identity

PY3 = sys.version_info[0] == 3


class JWTIdentityPolicy(object):
    """Morepath Identity Policy implementing JWT Access Auth.

    This class provides an IdentityPolicy implementation based on
    signed requests, using the JSON Web Token Authentication standard.

    Reference: http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
    """

    def __init__(self,
                 master_secret=None,
                 private_key=None,
                 private_key_file=None,
                 public_key=None,
                 public_key_file=None,
                 algorithm='HS256',
                 expiration_delta=datetime.timedelta(hours=6),
                 leeway=0,
                 verify_expiration=True,
                 issuer=None,
                 auth_header_prefix='JWT',
                 userid_claim='sub'
                 ):
            """Initiate the JWTIdentityPolicy with the given settings."""
            self.master_secret = master_secret
            self.private_key = private_key
            self.private_key_file = private_key_file
            self.public_key = public_key
            self.public_key_file = public_key_file
            self.algorithm = algorithm
            self.expiration_delta = expiration_delta
            self.leeway = leeway
            self.verify_expiration = verify_expiration
            self.issuer = issuer
            self.auth_header_prefix = auth_header_prefix
            self.userid_claim = userid_claim

    def identify(self, request):
        """Establish what identity this user claims to have from request.

        :param request: Request to extract identity information from.
        :type request: :class:`morepath.Request`.
        :returns: :class:`morepath.Identity` instance or
          :attr:`morepath.NO_IDENTITY` if identity cannot
          be established.
        """
        token = self.get_jwt(request)
        if token is None:
            return NO_IDENTITY
        claims_set = self.decode_jwt(token)
        if claims_set is None:
            return NO_IDENTITY
        userid = self.get_userid(claims_set)
        if userid is None:
            return NO_IDENTITY
        extra_claims = self.get_extra_claims(claims_set)
        if extra_claims is not None:
            return Identity(userid=userid, **extra_claims)
        else:
            return Identity(userid=userid)

    def remember(self, response, request, identity):
        """Remember identity on response.

        Implements ``morepath.remember_identity``, which is called
        from user login code.

        Create a JWT token and return it as the Authorization field of the response header.

        :param response: response object on which to store identity.
        :type response: :class:`morepath.Response`
        :param request: request object.
        :type request: :class:`morepath.Request`
        :param identity: identity to remember.
        :type identity: :class:`morepath.Identity`
        """
        extra_claims = identity.as_dict()
        userid = extra_claims.pop('userid')
        claims_set = self.create_claims_set(userid, extra_claims)
        token = self.encode_jwt(claims_set)
        response.headers['Authorization'] = '%s %s' % (self.auth_header_prefix, token)

    def forget(self, response, request):
        """Forget identity on response.

        Implements ``morepath.forget_identity``, which is called from
        user logout code.

        This is a no-op for this identity policy. The client is supposed to handle
        logout and remove the token.

        :param response: response object on which to forget identity.
        :type response: :class:`morepath.Response`
        :param request: request object.
        :type request: :class:`morepath.Request`
        """
        pass

    def decode_jwt(self, token):
        """Decode a JWTAuth token into its claims set.

        This method decodes the given JWT to provide the claims set.  The JWT can
        fail if the token has expired (with appropriate leeway) or if the
        token won't validate due to the secret (key) being wrong.

        If private_key/public key is set then the public_key will be used to
        decode the key.
        The leeway, issuer and verify_expiration settings will be passed to jwt.decode.

        :param token: the JWTAuth token.
        """
        key = self.master_secret
        public_key = self.public_key
        if self.public_key_file is not None:
            with open(self.public_key_file, 'r') as rsa_pub_file:
                public_key = rsa_pub_file.read()
        if public_key is not None:
            key = public_key
        if self.leeway is not None:
            leeway = self.leeway
        else:
            leeway = 0
        options = {
            'verify_exp': self.verify_expiration,
        }
        try:
            claims_set = jwt.decode(
                token,
                key,
                options=options,
                leeway=leeway,
                issuer=self.issuer
            )
        except (jwt.DecodeError, jwt.ExpiredSignature):
            return None
        return claims_set

    def create_claims_set(self, userid, extra_claims=None):
        """Create the claims set based on the userid of the claimed identity, the settings and the extra_claims dictionary.

        The userid will be stored in the registry.settings.jwtauth.userid_claim (default: "sub").
        If registry.settings.jwtauth.expiration_delta is set it will be added to the current time
        and stored in the "exp" claim.
        If registry.settings.jwtauth.issuer is set, it get stored in the "iss" claim.
        With the extra_claims dictionary you can provide additional claims. This can be registered claims like "nbf"
        (the datetime before which the token should not be processed) and/or claims containing extra info
        about the identity, which will be stored in the Identity object.

        :param userid:  the userid of the claimed identity.
        :param extra_claims: dictionary, containing additional claims or None.
        """
        expiration_delta = self.expiration_delta
        issuer = self.issuer
        userid_claim = self.userid_claim
        claims_set = {userid_claim: userid}
        if expiration_delta is not None:
            claims_set['exp'] = datetime.datetime.utcnow() + expiration_delta
        if issuer is not None:
            claims_set['iss'] = issuer
        if extra_claims is not None:
            claims_set.update(extra_claims)
        return claims_set

    def encode_jwt(self, claims_set):
        """Encode a JWT token based on the claims_set and the settings.

        If available, registry.settings.jwtauth.private_key is used as key.
        In this case the algorithm must be an RS* or EC* algorithm.
        If registry.settings.jwtauth.private_key is not set, registry.settings.jwtauth.master_secret is used.
        registry.settings.jwtauth.algorithm is used as algorithm.

        :param claims_set: set of claims, which will be included in the created token.
        """
        key = self.master_secret
        private_key = self.private_key
        if self.private_key_file is not None:
            with open(self.private_key_file, 'r') as rsa_priv_file:
                private_key = rsa_priv_file.read()
        if private_key is not None:
            key = private_key
        algorithm = self.algorithm
        token = jwt.encode(claims_set, key, algorithm)

        if PY3:
            token = token.decode(encoding='UTF-8')
        return token

    def get_userid(self, claims_set):
        """Extract the userid from a claims set.

        Returns userid or None if there is none.

        :param claims_set: set of claims, which was included in the received token.
        """
        userid_claim = self.userid_claim
        if userid_claim in claims_set:
            userid = claims_set[userid_claim]
        else:
            return None
        return userid

    def get_extra_claims(self, claims_set):
        """Get claims holding extra identity info from the claims set.

        Returns a dictionary of extra claims or None if there are none.

        :param claims_set: set of claims, which was included in the received token.
        """
        userid_claim = self.userid_claim
        reserved_claims = (userid_claim, "iss", "aud", "exp", "nbf", "iat", "jti")
        extra_claims = {}
        for claim in claims_set:
            if claim not in reserved_claims:
                extra_claims[claim] = claims_set[claim]
        if not extra_claims:
            return None
        return extra_claims

    def get_jwt(self, request):
        """Extract the JWT token from the authorisation header of the request.

        Returns the JWT token or None, if the token cannot be extracted.

        :param request: request object.
        :type request: :class:`morepath.Request`
        """
        auth_header_prefix = self.auth_header_prefix
        try:
            authorization = request.authorization
        except ValueError:
            return None
        if authorization is None:
            return None
        authtype, token = authorization
        if authtype.lower() != auth_header_prefix.lower():
            return None
        return token

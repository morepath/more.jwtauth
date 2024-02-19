"""Provides the JWTIdentityPolicy.

The following settings are available:

    * master_secret:  A secret known only by the server, used for
        the default HMAC (HS*) algorithm.

    * private_key:  An Elliptic Curve or an RSA private_key used for
        the EC (EC*) or RSA (PS*/RS*) algorithms.
    * private_key_file: A file holding an Elliptic Curve or an RSA encoded
        (PEM/DER) private_key.

    * public_key:  An Elliptic Curve or an RSA public_key used for the EC (EC*)
        or RSA (PS*/RS*) algorithms.
    * public_key_file: A file holding an Elliptic Curve
        or an RSA encoded (PEM/DER) public_key.

    * algorithm:  The algorithm used to sign the key (defaults to HS256).

    * expiration_delta: Time delta from now until the token will expire.
        This can either be a datetime.timedelta or the number of seconds.
        Default is 30 minutes, set to None to disable expiration.

    * leeway:  The leeway, which allows you to validate an expiration time
        which is in the past, but not very far. To use as a datetime.timedelta
        or the number of seconds. Defaults is 0.

    * allow_refresh: Enables the token refresh API when True.
        Default is False

    * refresh_delta: A time delta in which the token can be refreshed
        considering the leeway.
        This can either be a datetime.timedelta or the number of seconds.
        Default is 7 days. When None you can always refresh the token.

    * refresh_nonce_handler: Either dotted path to callback function or the
        callback function itself, which receives the userid as argument and
        returns a nonce which will be validated before refreshing.
        When None no nonce will be created or validated for refreshing.
        Default is None.

    * verify_expiration_on_refresh: If False, expiration_delta for the JWT
        token will not be checked during refresh. Otherwise you can refresh
        the token only if it's not yet expired. Default is False.

    * issuer: This is a string that will be checked against the iss claim of
        the token. You can use this e.g. if you have several related apps with
        exclusive user audience. Default is None (do not check iss on JWT).

    * auth_header_prefix: You can modify the Authorization header value prefix
        that is required to be sent together with the token. The default value
        is JWT. Another common value used for tokens is Bearer.

    * userid_claim: The claim, which contains the user id.
        The default claim is 'sub'.

The library takes either a master_secret or private_key/public_key pair.
In the later case the algorithm must be an EC*, PS* or RS* version.
"""

from calendar import timegm
from datetime import datetime, timedelta

import jwt
from morepath import NO_IDENTITY, Identity

from . import (
    DecodeError,
    ExpiredSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
)
from .utils import handler


class JWTIdentityPolicy:
    """Morepath Identity Policy implementing JWT Access Auth.

    This class provides an IdentityPolicy implementation based on
    signed requests, using the JSON Web Token Authentication standard.

    Reference:
    http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
    """

    def __init__(
        self,
        master_secret=None,
        private_key=None,
        private_key_file=None,
        public_key=None,
        public_key_file=None,
        algorithm="HS256",
        expiration_delta=timedelta(minutes=30),
        leeway=0,
        allow_refresh=False,
        refresh_delta=timedelta(days=7),
        refresh_nonce_handler=None,
        verify_expiration_on_refresh=False,
        issuer=None,
        auth_header_prefix="JWT",
        userid_claim="sub",
    ):
        """Initiate the JWTIdentityPolicy with the given settings."""
        _public_key = master_secret
        if public_key is not None:
            _public_key = public_key
        if public_key_file is not None:
            with open(public_key_file) as key_pub_file:
                _public_key = key_pub_file.read()
        self.public_key = _public_key

        _private_key = master_secret
        if private_key is not None:
            _private_key = private_key
        if private_key_file is not None:
            with open(private_key_file) as key_priv_file:
                _private_key = key_priv_file.read()
        self.private_key = _private_key

        self.algorithm = algorithm

        if isinstance(expiration_delta, timedelta):
            expiration_delta = expiration_delta.total_seconds()
        self.expiration_delta = expiration_delta

        if leeway is None:
            leeway = 0
        elif isinstance(leeway, timedelta):
            leeway = leeway.total_seconds()
        self.leeway = leeway

        self.allow_refresh = allow_refresh

        if isinstance(refresh_delta, timedelta):
            refresh_delta = refresh_delta.total_seconds()
        self.refresh_delta = refresh_delta

        if isinstance(refresh_nonce_handler, str):
            self.refresh_nonce_handler = handler(refresh_nonce_handler)
        else:
            self.refresh_nonce_handler = refresh_nonce_handler
        self.verify_expiration_on_refresh = verify_expiration_on_refresh
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
        try:
            claims_set = self.decode_jwt(token)
        except (DecodeError, ExpiredSignatureError):
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

        Implements ``morepath.App.remember_identity``, which is called
        from user login code.

        Create a JWT token and return it as the Authorization field of the
        response header.

        :param response: response object on which to store identity.
        :type response: :class:`morepath.Response`
        :param request: request object.
        :type request: :class:`morepath.Request`
        :param identity: identity to remember.
        :type identity: :class:`morepath.Identity`
        """
        claims = identity.as_dict()
        userid = claims.pop("userid")
        claims_set = self.create_claims_set(request, userid, claims)
        token = self.encode_jwt(claims_set)
        response.headers["Authorization"] = "{} {}".format(
            self.auth_header_prefix,
            token,
        )

    def forget(self, response, request):
        """Forget identity on response.

        Implements ``morepath.App.forget_identity``, which is called from
        user logout code.

        This is a no-op for this identity policy. The client is supposed to
        handle logout and remove the token.

        :param response: response object on which to forget identity.
        :type response: :class:`morepath.Response`
        :param request: request object.
        :type request: :class:`morepath.Request`
        """
        pass

    def decode_jwt(self, token, verify_expiration=True):
        """Decode a JWTAuth token into its claims set.

        This method decodes the given JWT to provide the claims set.  The JWT
        can fail if the token has expired (with appropriate leeway) or if the
        token won't validate due to the secret (key) being wrong.

        If private_key/public key is set then the public_key will be used
        to decode the key.
        The leeway and issuer settings will be passed to jwt.decode.

        :param token: the JWTAuth token.
        :param verify_expiration: if False the expiration time will not
            be checked.
        """
        options = {
            "verify_exp": verify_expiration,
        }
        return jwt.decode(
            token,
            self.public_key,
            algorithms=[self.algorithm],
            options=options,
            leeway=self.leeway,
            issuer=self.issuer,
        )

    def create_claims_set(self, request, userid, extra_claims=None):
        """Create the claims set based on the userid of the claimed identity,
        the settings and the extra_claims dictionary.

        The userid will be stored in settings.jwtauth.userid_claim
        (default: "sub").
        If settings.jwtauth.expiration_delta is set it will be added
        to the current time and stored in the "exp" claim.
        If settings.jwtauth.issuer is set, it get stored in the "iss" claim.
        If settings.jwtauth.refresh_delta is set it will be added
        to the current time and stored in the "refresh_until" claim and
        the return value of settings.jwtauth.refresh_nonce_handler called with
        "user_id" as argument will be stored in the "nonce" claim.

        With the extra_claims dictionary you can provide additional claims.
        This can be registered claims like "nbf"
        (the time before which the token should not be processed) and/or
        claims containing extra info
        about the identity, which will be stored in the Identity object.

        :param request: current request object.
        :type request: :class:`morepath.Request`
        :param userid:  the userid of the claimed identity.
        :param extra_claims: dictionary, containing additional claims or None.
        """
        claims_set = {self.userid_claim: userid}
        now = timegm(datetime.utcnow().utctimetuple())
        if self.expiration_delta is not None:
            claims_set["exp"] = now + self.expiration_delta
        if self.issuer is not None:
            claims_set["iss"] = self.issuer
        if self.allow_refresh:
            if self.refresh_delta is not None:
                claims_set["refresh_until"] = now + self.refresh_delta
            if self.refresh_nonce_handler is not None:
                claims_set["nonce"] = self.refresh_nonce_handler(
                    request, userid
                )
        if extra_claims is not None:
            claims_set.update(extra_claims)
        return claims_set

    def encode_jwt(self, claims_set):
        """Encode a JWT token based on the claims_set and the settings.

        If available, registry.settings.jwtauth.private_key is used as key.
        In this case the algorithm must be an RS* or EC* algorithm.
        If registry.settings.jwtauth.private_key is not set,
        registry.settings.jwtauth.master_secret is used.
        registry.settings.jwtauth.algorithm is used as algorithm.

        :param claims_set: set of claims, which will be included in
            the created token.
        """
        token = jwt.encode(
            claims_set,
            self.private_key,
            self.algorithm,
        )

        return token

    def get_userid(self, claims_set):
        """Extract the userid from a claims set.

        Returns userid or None if there is none.

        :param claims_set: set of claims, which was included
            in the received token.
        """
        if self.userid_claim in claims_set:
            return claims_set[self.userid_claim]
        else:
            return None

    def get_extra_claims(self, claims_set):
        """Get claims holding extra identity info from the claims set.

        Returns a dictionary of extra claims or None if there are none.

        :param claims_set: set of claims, which was included in the received
        token.
        """
        reserved_claims = (
            self.userid_claim,
            "iss",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
            "refresh_until",
            "nonce",
        )
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
        try:
            authorization = request.authorization
        except ValueError:  # pragma: no cover
            return None
        if authorization is None:
            return None
        authtype, token = authorization
        if authtype.lower() != self.auth_header_prefix.lower():
            return None
        return token

    def verify_refresh(self, request):
        """
        Verify if the request to refresh the token is valid.
        If valid it returns the userid which can be used to create
        an updated identity with ``remember_identity``.
        Otherwise it raises an exception based on InvalidTokenError.

        :param request: current request object
        :type request: :class:`morepath.Request`
        :returns: userid
        :raises: InvalidTokenError, ExpiredSignatureError, DecodeError,
            MissingRequiredClaimError
        """
        if not self.allow_refresh:
            raise InvalidTokenError("Token refresh is disabled")

        token = self.get_jwt(request)
        if token is None:
            raise InvalidTokenError("Token not found")

        try:
            claims_set = self.decode_jwt(
                token, self.verify_expiration_on_refresh
            )

        # reraise the exceptions to change the error messages
        except DecodeError:
            raise DecodeError("Token could not be decoded")
        except ExpiredSignatureError:
            raise ExpiredSignatureError("Token has expired")

        userid = self.get_userid(claims_set)
        if userid is None:
            raise MissingRequiredClaimError(self.userid_claim)

        if self.refresh_nonce_handler is not None:
            if "nonce" not in claims_set:
                raise MissingRequiredClaimError("nonce")
            if (
                self.refresh_nonce_handler(request, userid)
                != claims_set["nonce"]
            ):
                raise InvalidTokenError("Refresh nonce is not valid")

        if self.refresh_delta is not None:
            if "refresh_until" not in claims_set:
                raise MissingRequiredClaimError("refresh_until")
            now = timegm(datetime.utcnow().utctimetuple())
            refresh_until = int(claims_set["refresh_until"])
            if refresh_until < (now - self.leeway):
                raise ExpiredSignatureError("Refresh nonce has expired")

        return userid

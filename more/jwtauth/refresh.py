from .main import JWTIdentityPolicy


def verify_refresh_request(request):
    """
    Wrapper around JWTIdentityPolicy.verify_refresh which verify
    if the request to refresh the token is valid.
    If valid it returns the userid which can be used to
    create an updated identity with ``remember_identity``.
    Otherwise it raises an exception based on InvalidTokenError.

    :param request: request object
    :type request: :class:`morepath.Request`
    :returns: userid
    :raises: InvalidTokenError, ExpiredSignatureError, DecodeError,
        MissingRequiredClaimError
    """
    jwtauth_settings = request.app.settings.jwtauth.__dict__.copy()
    identity_policy = JWTIdentityPolicy(**jwtauth_settings)

    return identity_policy.verify_refresh(request)

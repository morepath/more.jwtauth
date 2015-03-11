more.jwtauth: JWT-Auth integration for Morepath
===============================================


Overview
--------

This is a Morepath_ authentication extension for the JSON Web Token (JWT) Authentication.

For more information about JWT, see:

-  `JSON Web Token draft`_ - the official JWT draft
-  `Auth with JSON Web Tokens`_ - an interesting blog post by José Padilla

To access resources using JWT Access Authentication, the client must have obtained a JWT to make signed requests to the server.
The Token can be opaque to client, although, unless it is encrypted, the client can read the claims made in the token.

This plugin uses the `PyJWT library`_ from José Padilla for verifying JWTs.


Requirements
------------

-  Python (2.7, 3.2, 3.3, 3.4)
-  morepath
-  PyJWT
-  cryptography (be sure to install all dependencies as referenced in https://cryptography.io/en/latest/installation)


Algorithms
----------

The JWT spec supports several algorithms for cryptographic signing. This library
currently supports:

* HS256 - HMAC using SHA-256 hash algorithm (default)
* HS384 - HMAC using SHA-384 hash algorithm
* HS512 - HMAC using SHA-512 hash algorithm
* ES256 - ECDSA signature algorithm using SHA-256 hash algorithm
* ES384 - ECDSA signature algorithm using SHA-384 hash algorithm
* ES512 - ECDSA signature algorithm using SHA-512 hash algorithm
* RS256 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-256 hash algorithm
* RS384 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-384 hash algorithm
* RS512 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-512 hash algorithm


Additional Settings
-------------------

There are some additional settings that you can override. Here are all the defaults::

    @JwtApp.setting_section(section="jwtauth")
    def get_jwtauth_settings():
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

The following settings are available:

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


Inspiration
-----------

This module is inspired by:

-  The pyramid_jwtauth_ package from Alex Kavanagh.
-  The django-rest-framework-jwt_ package from José Padilla.


.. _Morepath: http://morepath.readthedocs.org
.. _JSON Web Token draft: http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
.. _Auth with JSON Web Tokens: http://jpadilla.com/post/73791304724/auth-with-json-web-tokens
.. _PyJWT library: http://github.com/progrium/pyjwt
.. _pyramid_jwtauth: https://github.com/ajkavanagh/pyramid_jwtauth
.. _django-rest-framework-jwt: https://github.com/GetBlimp/django-rest-framework-jwt

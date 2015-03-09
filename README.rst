more.jwtauth: JWT-Auth integration for Morepath
===============================================

This is a Morepath_ authentication extension for the JSON Web Token (JWT) Authentication.

For more information about JWT, see:

-  `JSON Web Token draft`_ - the official JWT draft
-  `Auth with JSON Web Tokens`_ - an interesting blog post by José Padilla

To access resources using JWT Access Authentication, the client must have obtained a JWT to make signed requests to the server.
The Token can be opaque to client, although, unless it is encrypted, the client can read the claims made in the token.

This plugin uses the `PyJWT library`_ from José Padilla for verifying JWTs.


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

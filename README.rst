==========================================================================
more.jwtauth: JSON Web Token (JWT) Authentication integration for Morepath
==========================================================================

This is a Morepath_ authentication extension for JSON Web Token (JWT) Authentication:

http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
To access resources using JWT Access Authentication, the client must have obtained a JWT to make signed requests to the server. The Token can be opaque to client although, unless it is encrypted, the client can read the claims made in the token.

When accessing a protected resource, the server will generate a 401 challenge response with the scheme "JWT" as follows:

> GET /protected_resource HTTP/1.1
> Host: example.com

< HTTP/1.1 401 Unauthorized
< WWW-Authenticate: JWT

The client will use their JWT to build a request signature and include it in the Authorization header like so:

> GET /protected_resource HTTP/1.1
> Host: example.com
> Authorization: JWT eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
 cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

< HTTP/1.1 200 OK
< Content-Type: text/plain
<
< For your eyes only:  secret data!

(NB depending on the number of claims in the JWT the token can get large. For all practical purposes, it should be kept short.)

This plugin uses the PyJWT library for verifying JWTs:

http://github.com/progrium/pyjwt

Also see the library for generating the JWT for the client in the first place although any language can be used to generate it.


-----------
Inspiration
-----------

This module is inspired by:

* the pyramid_jwtauth package from Alex Kavanagh:
  https://github.com/ajkavanagh/pyramid_jwtauth

* the django-rest-framework-jwt package from José Padilla:
  https://github.com/GetBlimp/django-rest-framework-jwt


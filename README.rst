.. image:: https://github.com/morepath/more.jwtauth/workflows/CI/badge.svg?branch=master
   :target: https://github.com/morepath/more.jwtauth/actions?workflow=CI
   :alt: CI Status

.. image:: https://img.shields.io/pypi/v/more.jwtauth.svg
  :target: https://pypi.org/project/more.jwtauth/

.. image:: https://img.shields.io/pypi/pyversions/more.jwtauth.svg
  :target: https://pypi.org/project/more.jwtauth/


more.jwtauth: JWT Authentication integration for Morepath
=========================================================

Overview
--------

This is a Morepath_ authentication extension for the JSON Web Token (JWT)
Authentication.

For more information about JWT, see:

-  `JSON Web Token draft`_ - the official JWT draft
-  `Auth with JSON Web Tokens`_ - an interesting blog post by José Padilla

To access resources using JWT Access Authentication, the client must have
obtained a JWT to make signed requests to the server.
The Token can be opaque to client, although, unless it is encrypted,
the client can read the claims made in the token.

JWT validates the authenticity of the claimset using the signature.

This plugin uses the `PyJWT library`_ from José Padilla for verifying JWTs.

Introduction
------------

The general workflow of JWT Access Authentication:
    * After the client has sent the login form we check if the user
      exists and if the password is valid.
    * In this case more.jwtauth generates a JWT token including all
      information in a claim set and send it back to the client inside
      the HTTP authentication header.
    * The client stores it in some local storage and send it back in the
      authentication header on every request.
    * more.jwtauth validates the authenticity of the claim set using the
      signature included in the token.
    * The logout should be handled by the client by removing the token and
      making some cleanup depending on the implementation.

You can include all necessary information about the identity in the token
so JWT Access Authentication can be used by a stateless service e.g. with
external password validation.


Requirements
------------

-  Python (3.6, 3.7, 3.8, 3.9)
-  morepath (>= 0.19)
-  PyJWT (2.4.0)
-  optional: cryptography (>= 3.3.2)

.. Note::
   If you want to use another algorithm than HMAC (HS*), you need to install
   cryptography.
   On some systems this can be a little tricky. Please follow the instructions
   in https://cryptography.io/en/latest/installation.


Installation
------------

You can use pip for installing more.jwtauth:

* ``pip install -U more.jwtauth[crypto]`` - for installing with cryptography
* ``pip install -U more.jwtauth`` - installing without cryptography


Usage
-----

For a basic setup just set the necessary settings including a key or key file
and pass them to JWTIdentityPolicy:

.. code-block:: python

    import morepath
    from more.jwtauth import JWTIdentityPolicy


    class App(morepath.App):
        pass


    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            # Set a key or key file.
            'master_secret': 'secret',

            # Adjust the settings which you need.
            'leeway': 10
        }


    @App.identity_policy()
    def get_identity_policy(settings):
        # Get the jwtauth settings as a dictionary.
        jwtauth_settings = settings.jwtauth.__dict__.copy()

        # Pass the settings dictionary to the identity policy.
        return JWTIdentityPolicy(**jwtauth_settings)


    @App.verify_identity()
    def verify_identity(identity):
        # As we use a token based authentication
        # we can trust the claimed identity.
        return True

The login can be done in the standard Morepath way. You can add extra
information about the identity, which will be stored in the JWT token
and can be accessed through the morepath.Identity object:

.. code-block:: python

    class Login:
        pass


    @App.path(model=Login, path='login')
    def get_login():
        return Login()


    @App.view(model=Login, request_method='POST')
    def login(self, request):
        username = request.POST['username']
        password = request.POST['password']

        # Here you get some extra user information.
        email = request.POST['email']
        role = request.POST['role']

        # Do the password validation.
        if not user_has_password(username, password):
            raise HTTPProxyAuthenticationRequired('Invalid username/password')

        @request.after
        def remember(response):
            # We pass the extra info to the identity object.
            identity = morepath.Identity(username, email=email, role=role)
            request.app.remember_identity(response, request, identity)

        return "You're logged in."  # or something more fancy

Don't use reserved claim names as "iss", "aud", "exp", "nbf", "iat", "jti",
"refresh_until", "nonce" or the user_id_claim (default: "sub", see settings_).
They will be silently ignored.

Advanced:
    For testing or if we want to use some methods of the JWTIdentityPolicy
    class directly we can pass the settings as arguments to the class:

    .. code-block:: python

        identity_policy = JWTIdentityPolicy(
            master_secret='secret',
            leeway=10
        )


Refreshing the token
--------------------

There are some risks related with using long-term tokens:

* If you use a stateless solution the token contains user data which
  could not be up-to-date anymore.
* If a token get compromised there's no way to destroy sessions server-side.

A solution is to use short-term tokens and refresh them either just before
they expire or even after until the ``refresh_until`` claim not expires.

To help you with this more.jwtauth has a refresh API, which uses 4 settings:

* ``allow_refresh``: Enables the token refresh API when True.
    Default is False
* ``refresh_delta``: The time delta in which the token can be refreshed
    considering the leeway.
    Default is 7 days. When None you can always refresh the token.
* ``refresh_nonce_handler``: Either dotted path to callback function or the
    callback function itself, which receives the current request and the userid
    as arguments and returns a nonce which will be validated before refreshing.
    When None no nonce will be created or validated for refreshing.
* ``verify_expiration_on_refresh``: If False, expiration_delta for the JWT
    token will not be checked during refresh. Otherwise you can refresh the
    token only if it's not yet expired. Default is False.

When refreshing is enabled by setting ``refresh_delta`` the token can get
2 additional claims:

* ``refresh_until``: Timestamp until which the token can be refreshed.
* ``nonce``: The nonce which was generated by ``refresh_nonce_handler``.

So when you want to refresh your token, either because it has expires or
just before, you should adjust your jwtauth settings:

.. code-block:: python

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            # Set a key or key file.
            'master_secret': 'secret',
            'allow_refresh': True,
            'refresh_delta': 300,
            'refresh_nonce_handler': 'yourapp.handler.refresh_nonce_handler'
        }

Alternatively you can set the ``refresh_nonce_handler`` by decorating
a closure which returns the handler function:

.. code-block:: python

  from .app import App
  from .model import User


  @App.setting(section="jwtauth", name="refresh_nonce_handler")
  def get_handler():
    def refresh_nonce_handler(request, userid):
        # This returns a nonce from the user endity
        # which can just be an UUID you created before.
        return User.get(username=userid).nonce
      return refresh_nonce_handler

After you can send a request to the refresh end-point for refreshing the token:

.. code-block:: python

  from  morepath import Identity
  from more.jwtauth import (
      verify_refresh_request, InvalidTokenError, ExpiredSignatureError
  )

  from .app import App
  from .model import User


  class Refresh:
      pass


  @App.path(model=Refresh, path='refresh')
  def get_refresh():
      return Refresh()


  @App.view(model=Refresh)
  def refresh(self, request):
      try:
          # Verifies if we're allowed to refresh the token.
          # In this case returns the userid.
          # If not raises exceptions based on InvalidTokenError.
          # If expired this is a ExpiredSignatureError.
          username = verify_refresh_request(request)
      except ExpiredSignatureError:
          @request.after
          def expired_nonce_or_token(response):
              response.status_code = 403
          return "Your session has expired."
      except InvalidTokenError:
          @request.after
          def invalid_token(response):
              response.status_code = 403
          return "Could not refresh your token."
      else:
          # get user info from the database to update the claims
          User.get(username=username)

          @request.after
          def remember(response):
              # create the identity with the userid and updated user info
              identity = Identity(
                  username, email=user.email, role=user.role
              )
              # create the updated token and set it in the response header
              request.app.remember_identity(response, request, identity)

          return "Token sucessfully refreshed."

So now on every token refresh the user data gets updated.

When using the refresh_nonce_handler, you can just change the nonce
if the token gets compromised, e.g. by storing a new UUID in the user
endity, and the existing tokens will not be refreshed anymore.

Exceptions
~~~~~~~~~~

When refreshing the token fails, an exception is raised.
All exceptions are subclasses of ``more.jwtauth.InvalidTokenError``,
so you can catch them with ``except InvalidTokenError``.
For each exception a description of the failure is added.
The following exceptions could be raised:

* **InvalidTokenError**: A plain InvalidTokenError is used when the
  refreshing API is disabled, the JWT token could not be found or
  the refresh nonce is invalid.
* **ExpiredSignatureError**: when the ``refresh_until`` claim has expired
  or when the JWT token has expired in case ``verify_expiration_on_refresh`` is enabled.
* **MissingRequiredClaimError**: When the ``refresh_until`` claim is
  missing if a ``refresh_delta`` was provided or when the ``nonce``
  claim is missing if ``refresh_nonce_handler`` is in use.
* **DecodeError**: When the JWT token could not be decoded.


Settings
--------

There are some settings that you can override. Here are all the defaults:

.. code-block:: python

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': None,
            'private_key': None,
            'private_key_file': None,
            'public_key': None,
            'public_key_file': None,
            'algorithm': "HS256",
            'expiration_delta': datetime.timedelta(minutes=30),
            'leeway': 0,
            'allow_refresh': False,
            'refresh_delta': timedelta(days=7),
            'refresh_nonce_handler': None,
            'verify_expiration_on_refresh': False,
            'issuer': None,
            'auth_header_prefix': "JWT",
            'userid_claim': "sub"
        }

The following settings are available:

master_secret
  A secret known only by the server, used for the default HMAC (HS*) algorithm.
  Default is None.

private_key
  An Elliptic Curve or an RSA private_key used for the EC (EC*)
  or RSA (PS*/RS*) algorithms. Default is None.

private_key_file
  A file holding an Elliptic Curve or an RSA encoded (PEM/DER) private_key.
  Default is None.

public_key
  An Elliptic Curve or an RSA public_key used for the EC (EC*) or RSA (PS*/RS*)
  algorithms. Default is None.

public_key_file
  A file holding an Elliptic Curve or an RSA encoded (PEM/DER) public_key.
  Default is None.

algorithm
  The algorithm used to sign the key.
  Defaults is HS256.

expiration_delta
  Time delta from now until the token will expire. Set to None to disable.
  This can either be a datetime.timedelta or the number of seconds.
  Default is 30 minutes.

leeway
  The leeway, which allows you to validate an expiration time which is in the
  past, but not very far. To use either as a datetime.timedelta or the number
  of seconds. Defaults is 0.

allow_refresh
  Setting to True enables the refreshing API.
  Default is False

refresh_delta
  A time delta in which the token can be refreshed considering the leeway.
  This can either be a datetime.timedelta or the number of seconds.
  Default is 7 days. When None you can always refresh the token.

refresh_nonce_handler
  Dotted path to callback function, which receives the userid as argument and
  returns a nonce which will be validated before refreshing.
  When None no nonce will be created or validated for refreshing.
  Default is None.

verify_expiration_on_refresh
  If False, expiration_delta for the JWT token will not be checked during
  refresh. Otherwise you can refresh the token only if it's not yet expired.
  Default is False.

issuer
  This is a string that will be checked against the iss claim of the token.
  You can use this e.g. if you have several related apps with exclusive user
  audience. Default is None (do not check iss on JWT).

auth_header_prefix
  You can modify the Authorization header value prefix that is required to be
  sent together with the token. The default value is JWT.
  Another common value used for tokens is Bearer.

userid_claim
  The claim, which contains the user id.
  The default claim is 'sub'.

The library takes either a master_secret or private_key/public_key pair.
In the later case the algorithm must be an EC*, PS* or RS* version.


Algorithms
----------

The JWT spec supports several algorithms for cryptographic signing.
This library currently supports:

HS256
  HMAC using SHA-256 hash algorithm (default)

HS384
  HMAC using SHA-384 hash algorithm

HS512
   HMAC using SHA-512 hash algorithm

ES256 [1]_
  ECDSA signature algorithm using SHA-256 hash algorithm

ES384 [1]_
  ECDSA signature algorithm using SHA-384 hash algorithm

ES512 [1]_
  ECDSA signature algorithm using SHA-512 hash algorithm

PS256 [1]_
  RSASSA-PSS signature using SHA-256 and MGF1 padding with SHA-256

PS384 [1]_
  RSASSA-PSS signature using SHA-384 and MGF1 padding with SHA-384

PS512 [1]_
  RSASSA-PSS signature using SHA-512 and MGF1 padding with SHA-512

RS256 [1]_
  RSASSA-PKCS1-v1_5 signature algorithm using SHA-256 hash algorithm

RS384 [1]_
  RSASSA-PKCS1-v1_5 signature algorithm using SHA-384 hash algorithm

RS512 [1]_
  RSASSA-PKCS1-v1_5 signature algorithm using SHA-512 hash algorithm

.. [1] The marked algorithms require more.jwtauth to be installed
  with its ``crypto`` dependencies::

    .. code-block:: console

        pip install -U more.jwtauth[crypto]

    See Installation_ for details. In case of problems be sure
    to have read the note in the Requirements_ section.


Developing more.jwtauth
=======================

Install more.jwtauth for development
------------------------------------

Clone more.jwtauth from github::

.. code-block:: console

  git clone git@github.com:morepath/more.jwtauth.git

If this doesn't work and you get an error 'Permission denied (publickey)',
you need to upload your ssh public key to github_.

Then go to the more.jwtauth directory::

.. code-block:: console

  cd more.jwtauth

Make sure you have virtualenv_ installed.

Create a new virtualenv inside the more.jwtauth directory::

.. code-block:: console

  python -m venv .venv

Activate the virtualenv::

.. code-block:: console

  source .venv/bin/activate

Inside the virtualenv make sure you have recent setuptools and pip installed::

.. code-block:: console

  pip install -U setuptools pip

Install the various dependencies and development tools from
develop_requirements.txt::

.. code-block:: console

  pip install -Ur develop_requirements.txt

For upgrading the requirements just run the command again.

.. note::

   The following commands work only if you have the virtualenv activated.

Install pre-commit hook for Black integration
---------------------------------------------

We're using Black_ for formatting the code and it's recommended to
install the `pre-commit hook`_ for Black integration before committing::

  pre-commit install

.. _`pre-commit hook`: https://black.readthedocs.io/en/stable/version_control_integration.html

Running the tests
-----------------

You can run the tests using `pytest`_::

.. code-block:: console

  pytest

To generate test coverage information as HTML do::

.. code-block:: console

  pytest --cov --cov-report html

You can then point your web browser to the ``htmlcov/index.html`` file
in the project directory and click on modules to see detailed coverage
information.

.. _`pytest`: http://pytest.org/latest/

Black
-----

To format the code with the `Black Code Formatter`_ run in the root directory::

  black .

Black has also `integration`_ for the most popular editors.

.. _`Black Code Formatter`: https://black.readthedocs.io
.. _`integration`: https://black.readthedocs.io/en/stable/editor_integration.html

Various checking tools
----------------------

flake8_ is a tool that can do various checks for common Python
mistakes using pyflakes_, check for PEP8_ style compliance and
can do `cyclomatic complexity`_ checking. To do pyflakes and pep8
checking do::

.. code-block:: console

  flake8 more.jwtauth

To also show cyclomatic complexity, use this command::

.. code-block:: console

  flake8 --max-complexity=10 more.jwtauth

Tox
---

With tox you can test Morepath under different Python environments.

We have Travis continuous integration installed on Morepath's github
repository and it runs the same tox tests after each checkin.

First you should install all Python versions which you want to
test. The versions which are not installed will be skipped. You should
at least install Python 3.7 which is required by flake8, coverage and
doctests.

One tool you can use to install multiple versions of Python is pyenv_.

To find out which test environments are defined for Morepath in tox.ini run::

.. code-block:: console

  tox -l

You can run all tox tests with::

.. code-block:: console

  tox

You can also specify a test environment to run e.g.::

.. code-block:: console

  tox -e py37
  tox -e pep8
  tox -e coverage


.. _Morepath: http://morepath.readthedocs.org
.. _JSON Web Token draft:
    http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
.. _Auth with JSON Web Tokens:
    http://jpadilla.com/post/73791304724/auth-with-json-web-tokens
.. _PyJWT library: http://github.com/progrium/pyjwt
.. _github: https://help.github.com/articles/generating-an-ssh-key
.. _virtualenv: https://pypi.python.org/pypi/virtualenv
.. _flake8: https://pypi.python.org/pypi/flake8
.. _pyflakes: https://pypi.python.org/pypi/pyflakes
.. _pep8: http://www.python.org/dev/peps/pep-0008/
.. _`cyclomatic complexity`:
    https://en.wikipedia.org/wiki/Cyclomatic_complexity
.. _pyenv: https://github.com/yyuu/pyenv

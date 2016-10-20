more.jwtauth: JWT Authentication integration for Morepath
=========================================================


Overview
--------

This is a Morepath_ authentication extension for the JSON Web Token (JWT) Authentication.

For more information about JWT, see:

-  `JSON Web Token draft`_ - the official JWT draft
-  `Auth with JSON Web Tokens`_ - an interesting blog post by José Padilla

To access resources using JWT Access Authentication, the client must have obtained a JWT to make signed requests to the server.
The Token can be opaque to client, although, unless it is encrypted, the client can read the claims made in the token.

JWT validates the authenticity of the claimset using the signature.

This plugin uses the `PyJWT library`_ from José Padilla for verifying JWTs.

Introduction
------------

The general workflow of JWT Access Authentication:
    * After the client has sent the login form we check if the user exists and if the password is valid.
    * In this case more.jwtauth generates a JWT token including all information in a claim set and send
      it back to the client inside the HTTP authentication header.
    * The client stores it in some local storage and send it back in the authentication header on every request.
    * more.jwtauth validates the authenticity of the claim set using the signature included in the token.
    * The logout should be handled by the client by removing the token and making some cleanup depending on the
      implementation.

You can include all necessary information about the identity in the token so JWT Access Authentication
can be used by a stateless service e.g. with external password validation.


Requirements
------------

-  Python (2.7, 3.3, 3.4, 3.5)
-  morepath (>= 0.16.1)
-  PyJWT (1.4.2)
-  optional: cryptography (1.5.2)

.. Note::
   If you want to use another algorithm than HMAC (HS*), you need to install
   cryptography.
   On some systems this can be a little tricky. Please follow the instructions
   in https://cryptography.io/en/latest/installation and be sure to install all
   dependencies as referenced.


Installation
------------

You can use pip for installing more.jwtauth:

* ``pip install -U more.jwtauth[crypto]`` - for installing with cryptography
* ``pip install -U more.jwtauth`` - installing without cryptography


Usage
-----

For a basic setup just set the necessary settings including a key or key file
and pass them to JWTIdentityPolicy::

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
        # As we use a token based authentication we can trust the claimed identity.
        return True

The login can be done in the standard Morepath way. You can add extra information about the identity,
which will be stored in the JWT token and can be accessed through the morepath.Identity object::

    class Login(object):
        pass


    @App.path(model=Login, path='login')
    def get_login():
        return Login()


    @App.view(model=Login, request_method='POST')
    def login(self, request):
        username = request.POST['username']
        password = request.POST['password']

        # Here you get some extra user information.
        fullname = request.POST['fullname']
        email = request.POST['email']
        role = request.POST['role']

        # Do the password validation.
        if not user_has_password(username, password):
            raise HTTPProxyAuthenticationRequired('Invalid username/password')

        @request.after
        def remember(response):
            # We pass the extra info to the identity object.
            identity = morepath.Identity(username, fullname=fullname, email=email, role=role)
            request.app.remember_identity(response, request, identity)

        return "You're logged in."  # or something more fancy

Don't use reserved claim names as "iss", "aud", "exp", "nbf", "iat", "jti" and
the user_id_claim (default: "sub", see settings_). They will be silently ignored.

Advanced:
    For testing or if we want to use some methods of the JWTIdentityPolicy class
    directly we can pass the settings as arguments to the class::

        identity_policy = JWTIdentityPolicy(
            master_secret='secret',
            leeway=10
        )


Algorithms
----------

The JWT spec supports several algorithms for cryptographic signing. This library
currently supports:

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

         pip install -U more.jwtauth[crypto]

       See Installation_ for details. In case of problems be sure
       to have read the note in the Requirements_ section.


Settings
--------

There are some settings that you can override. Here are all the defaults::

    @App.setting_section(section="jwtauth")
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

master_secret
   A secret known only by the server, used for the default HMAC (HS*) algorithm.
   Default is None.

private_key
   An Elliptic Curve or an RSA private_key used for the EC (EC*) or RSA (PS*/RS*) algorithms.
   Default is None.

private_key_file
   A file holding an Elliptic Curve or an RSA encoded (PEM/DER) private_key.
   Default is None.

public_key
   An Elliptic Curve or an RSA public_key used for the EC (EC*) or RSA (PS*/RS*) algorithms.
   Default is None.

public_key_file
   A file holding an Elliptic Curve or an RSA encoded (PEM/DER) public_key.
   Default is None.

algorithm
   The algorithm used to sign the key.
   Defaults is HS256.

expiration_delta
   Time delta from now until the token will expire. Set to None to disable.
   Default is 6 hours.

leeway
   The leeway, which allows you to validate an expiration time which is in the past, but not very far.
   To use as a datetime.timedelta.
   Defaults is 0.

verify_expiration
   If you set it to False and expiration_delta is not None, you should verify the "exp" claim by yourself
   and if it is expired you can either refresh the token or you must reject it.
   Default is True.

issuer
   This is a string that will be checked against the iss claim of the token.
   You can use this e.g. if you have several related apps with exclusive user audience.
   Default is None (do not check iss on JWT).

auth_header_prefix
   You can modify the Authorization header value prefix that is required to be sent together with the token.
   The default value is JWT. Another common value used for tokens is Bearer.

userid_claim
   The claim, which contains the user id.
   The default claim is 'sub'.

The library takes either a master_secret or private_key/public_key pair.
In the later case the algorithm must be an EC*, PS* or RS* version.


Developing more.jwtauth
=======================

Install more.jwtauth for development
------------------------------------

.. highlight:: console

Clone more.jwtauth from github::

  $ git clone git@github.com:morepath/more.jwtauth.git

If this doesn't work and you get an error 'Permission denied (publickey)',
you need to upload your ssh public key to github_.

Then go to the more.jwtauth directory::

  $ cd more.jwtauth

Make sure you have virtualenv_ installed.

Create a new virtualenv for Python 3 inside the more.jwtauth directory::

  $ virtualenv -p python3 env/py3

Activate the virtualenv::

  $ source env/py3/bin/activate

Make sure you have recent setuptools and pip installed::

  $ pip install -U setuptools pip

Install the various dependencies and development tools from
develop_requirements.txt::

  $ pip install -Ur develop_requirements.txt

For upgrading the requirements just run the command again.

If you want to test more.jwtauth with Python 2.7 as well you can create a
second virtualenv for it::

  $ virtualenv -p python2.7 env/py27

You can then activate it::

  $ source env/py27/bin/activate

Then uprade setuptools and pip and install the develop requirements as
described above.

.. note::

   The following commands work only if you have the virtualenv activated.

Running the tests
-----------------

You can run the tests using `py.test`_::

  $ py.test

To generate test coverage information as HTML do::

  $ py.test --cov --cov-report html

You can then point your web browser to the ``htmlcov/index.html`` file
in the project directory and click on modules to see detailed coverage
information.

.. _`py.test`: http://pytest.org/latest/

Various checking tools
----------------------

flake8_ is a tool that can do various checks for common Python
mistakes using pyflakes_, check for PEP8_ style compliance and
can do `cyclomatic complexity`_ checking. To do pyflakes and pep8
checking do::

  $ flake8 more.jwtauth

To also show cyclomatic complexity, use this command::

  $ flake8 --max-complexity=10 more.jwtauth

Tox
---

With tox you can test Morepath under different Python environments.

We have Travis continuous integration installed on Morepath's github
repository and it runs the same tox tests after each checkin.

First you should install all Python versions which you want to
test. The versions which are not installed will be skipped. You should
at least install Python 3.5 which is required by flake8, coverage and
doctests and Python 2.7 for testing Morepath with Python 2.

One tool you can use to install multiple versions of Python is pyenv_.

To find out which test environments are defined for Morepath in tox.ini run::

  $ tox -l

You can run all tox tests with::

  $ tox

You can also specify a test environment to run e.g.::

  $ tox -e py35
  $ tox -e pep8
  $ tox -e coverage


.. _Morepath: http://morepath.readthedocs.org
.. _JSON Web Token draft: http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
.. _Auth with JSON Web Tokens: http://jpadilla.com/post/73791304724/auth-with-json-web-tokens
.. _PyJWT library: http://github.com/progrium/pyjwt
.. _github: https://help.github.com/articles/generating-an-ssh-key
.. _virtualenv: https://pypi.python.org/pypi/virtualenv
.. _flake8: https://pypi.python.org/pypi/flake8
.. _pyflakes: https://pypi.python.org/pypi/pyflakes
.. _pep8: http://www.python.org/dev/peps/pep-0008/
.. _`cyclomatic complexity`: https://en.wikipedia.org/wiki/Cyclomatic_complexity
.. _pyenv: https://github.com/yyuu/pyenv

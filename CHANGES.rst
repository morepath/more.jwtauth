CHANGES
=======

0.14 (2024-03-02)
-----------------

- Upgrade PyJWT and Cryptography dependencies.

- Fix test_refresh.

- **Removed**: Drop support for Python 3.6 and 3.7.

- Add support for Python 3.10, 3.11 and 3.12.

- Show full diffs in the test output.

- Update pre-commit revs.

- Adjust README.


0.13 (2022-06-19)
-----------------

- Remove obsolete decoding of encoded token.

- Upgrade PyJWT and Cryptography dependencies.

- Drop support for Python 3.5.

- Add support for Python 3.9.

- Use GitHub Actions for CI.


0.12 (2020-04-26)
-----------------

- **Removed**: Removed support for Python 2 and Python 3.4.
  
  You have to upgrade to Python 3 if you want to use this version.

- Added support for Python 3.7 and 3.8 and PyPy 3.6.

- Make Python 3.7 the default testing environment.

- Upgrade PyJWT to version 1.7.1 and cryptography to version 2.9.2.

- Add integration for the Black code formatter.


0.11 (2018-01-18)
-----------------

- Remove support for Python 3.3 and add support for Python 3.6.
- Upgrade PyJWT to version 1.5.3 and cryptography to version 2.1.4.


0.10 (2017-12-08)
-----------------

- **Breaking:** Add request parameter to refresh_nonce_handler (see issue `#8`_).

.. _#8: https://github.com/morepath/more.jwtauth/issues/8


0.9 (2017-03-02)
----------------

- **New:** Add an API to refresh the JWT token (see issue `#6`_).

  This implement adding 4 new settings:

  * ``allow_refresh``: Enables the token refresh API when True.
  * ``refresh_delta``: The time delta in which the token can be refreshed
    considering the leeway.
  * ``refresh_nonce_handler``: Dotted path to callback function, which receives
    the userid as argument and returns a nonce which will be validated before
    refreshing.
  * ``verify_expiration_on_refresh``: If False, expiration_delta for the JWT
    token will not be checked during refresh.
    Otherwise you can refresh the token only if it's not yet expired.

  It also adds 2 claims to the token when refreshing is enabled:

  * ``refresh_until``: Timestamp until which the token can be refreshed.
  * ``nonce``: The nonce which was returned by ``refresh_nonce_handler``.

  For details see README.rst.

- **Removed:** The ``verify_expiration`` setting has been removed as it was
  mainly for custom handling of token refreshing, which is now obsolete.

- Pass algorithm explicit to ``jwt.decode()`` to avoid some vulnerabilities.
  For details see the blog post by Tim McLean about some
  "`Critical vulnerabilities in JSON Web Token libraries`_".

- Allow expiration_delta and leeway as number of seconds in addition to
  datetime.timedelta.

- Some code cleanup and refactoring.

.. _#6: https://github.com/morepath/more.jwtauth/issues/6
.. _Critical vulnerabilities in JSON Web Token libraries:
  https://www.chosenplaintext.ca/2015/03/31/jwt-algorithm-confusion.html


0.8 (2016-10-21)
----------------

- We now use virtualenv and pip instead of buildout to set up the
  development environment. A development section has been
  added to the README accordingly.
- Review and optimize the tox configuration.
- Upgrade to PyJWT 1.4.2 and Cryptography 1.5.2.


0.7 (2016-07-20)
----------------

- Upgrade to Morepath 0.15.
- Upgrade to PyJWT 1.4.1 and Cryptography 1.4.
- Add testenv for Python 3.5 and make it the default test environment.
- Change author to "Morepath developers".
- Clean up classifiers.


0.6 (2016-05-19)
----------------

- Make Cryptography optional.

  **Breaking Change:** For using other algorithms than HMAC you now need
  to install the ``crypto`` dependencies explicitly. Read the note in the
  Requirements section and the new Installation section of README.rst.

- Add an Installation section to the README.
- Refactor the cryptography test suite.


0.5 (2016-04-25)
----------------

- Adding some tests.
- Increase coverage to 100%.
- Add travis-ci and tox integration.
- Some clean-up.
- Upgrade to Morepath 0.14.
- Some improvements to the setup and release workflow.



0.4 (2016-04-13)
----------------

- Upgrade to Morepath 0.13.2 and update the tests.
- Upgrade PyJWT to 1.3.0 and cryptography to 1.3.1.
- Make it a PyPI package and release it. Fixes Issue #1.


0.3 (2016-04-13)
----------------

- Upgrade PyJWT to 1.4.0 and cryptography to 0.9.1.
- Python 3.2 is no longer a supported platform. This version of Python is rarely used.
  PyUsers affected by this should upgrade to 3.3+.
- Some cleanup.

0.2 (2015-06-29)
----------------

- Integrate the set_jwt_auth_header function into the identity policy as remember method.

- Add support for PS256, PS384, and PS512 algorithms.

- Pass settings directly as arguments to the JWTIdentityPolicy class with the possibility
  to override them with Morepath settings using the method introduced in Morepath 0.11.

- Remove JwtApp as now we use JWTIdentityPolicy directly without inherit from JwtApp.

- Add a Introduction and Usage section to README.

- Integrate all functions as methods in the JWTIdentityPolicy Class.

- Refactor the test suite.


0.1 (2015-04-15)
----------------

- Initial public release.

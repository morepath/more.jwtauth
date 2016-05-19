CHANGES
*******

0.6 (2016-05-19)
================

- Make Cryptography optional.

  **Breaking Change:** For using other algorithms than HMAC you now need
  to install the ``crypto`` dependencies explicitly. Read the note in the
  Requirements section and the new Installation section of README.rst.

- Add an Installation section to the README.
- Refactor the cryptography test suite.


0.5 (2016-04-25)
================

- Adding some tests.
- Increase coverage to 100%.
- Add travis-ci and tox integration.
- Some clean-up.
- Upgrade to Morepath 0.14.
- Some improvements to the setup and release workflow.



0.4 (2016-04-13)
================

- Upgrade to morepath 0.13.2 and update the tests.
- Upgrade PyJWT to 1.3.0 and cryptography to 1.3.1.
- Make it a PyPI package and release it. Fixes Issue #1.


0.3 (2016-04-13)
================

- Upgrade PyJWT to 1.4.0 and cryptography to 0.9.1.
- Python 3.2 is no longer a supported platform. This version of Python is rarely used.
  PyUsers affected by this should upgrade to 3.3+.
- Some cleanup.

0.2 (2015-06-29)
================

- Integrate the set_jwt_auth_header function into the identity policy as remember method.

- Add support for PS256, PS384, and PS512 algorithms.

- Pass settings directly as arguments to the JWTIdentityPolicy class with the possibility
  to override them with Morepath settings using the method introduced in Morepath 0.11.

- Remove JwtApp as now we use JWTIdentityPolicy directly without inherit from JwtApp.

- Add a Introduction and Usage section to README.

- Integrate all functions as methods in the JWTIdentityPolicy Class.

- Refactor the test suite.


0.1 (2015-04-15)
================

- Initial public release.

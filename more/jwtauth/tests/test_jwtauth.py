# -*- coding: utf-8 -*-
import datetime
import morepath
from morepath import (Response, settings, Identity, NO_IDENTITY)

from more.jwtauth import JwtApp
from more.jwtauth.main import JWTIdentityPolicy
import more.jwtauth.main
from webob import Request
from webob.exc import HTTPForbidden, HTTPProxyAuthenticationRequired
from webtest import TestApp as Client


def setup_module(module):
    morepath.disable_implicit()


def test_jwt_default_settings():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    config.commit()
    lookup = App().registry.lookup

    assert settings(lookup=lookup).jwtauth.algorithm == "HS256"
    assert settings(lookup=lookup).jwtauth.auth_header_prefix == "JWT"
    assert settings(lookup=lookup).jwtauth.master_secret is None


def test_jwt_custom_settings():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'public_key': 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBWcJwPEAnS/k4kFgUhxNF7J0SQQhZG+nNgy+/mXwhQ5PZIUmId1a1TjkNXiKzv6DpttBqduHbz/V0EtH+QfWy0B4BhZ5MnTyDGjcz1DQqKdexebhzobbhSIZjpYd5aU48o9rXp/OnAnrajddpGsJ0bNf4rtMLBqFYJN6LOslAB7xTBRg=',
            'algorithm': "ES256",
            'leeway': 20
        }

    config.commit()
    lookup = App().registry.lookup

    assert settings(lookup=lookup).jwtauth.algorithm == "ES256"
    assert settings(lookup=lookup).jwtauth.master_secret is None
    assert settings(lookup=lookup).jwtauth.leeway == 20
    assert settings(lookup=lookup).jwtauth.public_key == 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBWcJwPEAnS/k4kFgUhxNF7J0SQQhZG+nNgy+/mXwhQ5PZIUmId1a1TjkNXiKzv6DpttBqduHbz/V0EtH+QfWy0B4BhZ5MnTyDGjcz1DQqKdexebhzobbhSIZjpYd5aU48o9rXp/OnAnrajddpGsJ0bNf4rtMLBqFYJN6LOslAB7xTBRg='


def test_encode_decode():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'secret',
        }

    config.commit()
    lookup = App().registry.lookup
    claims_set = {
        'sub': 'user'
    }
    token = more.jwtauth.main.encode_jwt(claims_set, settings(lookup=lookup).jwtauth)
    claims_set_decoded = more.jwtauth.main.decode_jwt(token, settings(lookup=lookup).jwtauth)

    assert claims_set_decoded == claims_set


def test_encode_decode_with_unicode():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'sëcret',
        }

    config.commit()
    lookup = App().registry.lookup
    claims_set = {
        'sub': 'user'
    }
    token = more.jwtauth.main.encode_jwt(claims_set, settings(lookup=lookup).jwtauth)
    claims_set_decoded = more.jwtauth.main.decode_jwt(token, settings(lookup=lookup).jwtauth)

    assert claims_set_decoded == claims_set


def test_encode_decode_with_es256():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'algorithm': "ES256",
            'private_key_file': 'more/jwtauth/tests/keys/testkey_ec',
            'public_key_file': 'more/jwtauth/tests/keys/testkey_ec.pub',
        }

    config.commit()
    lookup = App().registry.lookup
    claims_set = {
        'sub': 'user'
    }
    token = more.jwtauth.main.encode_jwt(claims_set, settings(lookup=lookup).jwtauth)
    claims_set_decoded = more.jwtauth.main.decode_jwt(token, settings(lookup=lookup).jwtauth)

    assert claims_set_decoded == claims_set


def test_encode_decode_with_rs512():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'algorithm': "RS512",
            'private_key_file': 'more/jwtauth/tests/keys/testkey_rsa',
            'public_key_file': 'more/jwtauth/tests/keys/testkey_rsa.pub',
        }

    config.commit()
    lookup = App().registry.lookup
    claims_set = {
        'sub': 'user'
    }
    token = more.jwtauth.main.encode_jwt(claims_set, settings(lookup=lookup).jwtauth)
    claims_set_decoded = more.jwtauth.main.decode_jwt(token, settings(lookup=lookup).jwtauth)

    assert claims_set_decoded == claims_set


def test_create_claim_and_encode_decode_and_get_userid_and_get_extra_claims():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'secret',
        }

    config.commit()
    lookup = App().registry.lookup
    userid = 'user'
    extra_claims = {
        'email': 'user@example.com',
        'role': 'admin'
    }
    claims_set = more.jwtauth.main.create_claims_set(userid, settings(lookup=lookup).jwtauth, extra_claims)
    token = more.jwtauth.main.encode_jwt(claims_set, settings(lookup=lookup).jwtauth)
    claims_set_decoded = more.jwtauth.main.decode_jwt(token, settings(lookup=lookup).jwtauth)

    assert userid == more.jwtauth.main.get_userid(claims_set_decoded, settings(lookup=lookup).jwtauth)
    assert extra_claims == more.jwtauth.main.get_extra_claims(claims_set_decoded, settings(lookup=lookup).jwtauth)


def test_create_claim_and_encode_decode_expired():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'secret',
            'expiration_delta': datetime.timedelta(seconds=-2),
        }

    config.commit()
    lookup = App().registry.lookup
    userid = 'user'
    claims_set = more.jwtauth.main.create_claims_set(userid, settings(lookup=lookup).jwtauth)
    token = more.jwtauth.main.encode_jwt(claims_set, settings(lookup=lookup).jwtauth)
    claims_set_decoded = more.jwtauth.main.decode_jwt(token, settings(lookup=lookup).jwtauth)

    assert claims_set_decoded is None


def test_create_claim_and_encode_decode_expired_but_with_leeway():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'secret',
            'expiration_delta': datetime.timedelta(seconds=-2),
            'leeway': 3
        }

    config.commit()
    lookup = App().registry.lookup
    userid = 'user'
    claims_set = more.jwtauth.main.create_claims_set(userid, settings(lookup=lookup).jwtauth)
    token = more.jwtauth.main.encode_jwt(claims_set, settings(lookup=lookup).jwtauth)
    claims_set_decoded = more.jwtauth.main.decode_jwt(token, settings(lookup=lookup).jwtauth)

    assert more.jwtauth.main.get_userid(claims_set_decoded, settings(lookup=lookup).jwtauth) == userid


def test_authorization():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'secret',
        }

    config.commit()
    request = App().request(Request.blank(path='').environ)
    lookup = App().registry.lookup
    auth_header = more.jwtauth.main.set_jwt_auth_header(request, 'user')
    request.authorization = auth_header
    token = more.jwtauth.main.get_jwt(request, settings(lookup=lookup).jwtauth)
    claims_set_decoded = more.jwtauth.main.decode_jwt(token, settings(lookup=lookup).jwtauth)

    assert more.jwtauth.main.get_userid(claims_set_decoded, settings(lookup=lookup).jwtauth) == 'user'


def test_encode_jwt_raw():
    import jwt
    from sys import version_info
    claims_set = {
        'sub': 'user'
    }
    key = 'secret'
    token = jwt.encode(claims_set, key)
    if version_info >= (3, 0, 0):
        token = token.decode(encoding='UTF-8')

    assert token == 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.' \
                    '8jVjALlPRYpE03sMD8kuqG9D4RSih5NjiISNZ-wO3oY'


def test_encode_jwt():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'secret',
            'expiration_delta': None,
        }

    config.commit()
    lookup = App().registry.lookup
    claims_set = {
        'sub': 'user'
    }
    token = more.jwtauth.main.encode_jwt(claims_set, settings(lookup=lookup).jwtauth)

    assert token == 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.' \
                    '8jVjALlPRYpE03sMD8kuqG9D4RSih5NjiISNZ-wO3oY'

    claims_set_decoded = more.jwtauth.main.decode_jwt(token, settings(lookup=lookup).jwtauth)

    assert more.jwtauth.main.get_userid(claims_set_decoded, settings(lookup=lookup).jwtauth) == 'user'


def test_login():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'secret',
            'expiration_delta': None,
        }

    class Login(object):
        pass

    @App.path(model=Login, path='login')
    def get_login():
        return Login()

    @App.json(model=Login, request_method='POST')
    def login(self, request):
        username = request.POST['username']
        password = request.POST['password']
        if not user_has_password(username, password):
            raise HTTPProxyAuthenticationRequired('Invalid username/password')
        @request.after
        def set_auth_header(response):
            auth_header = more.jwtauth.main.set_jwt_auth_header(request, username)
            response.headers['Authorization'] = auth_header
        return {
            'username': username,
        }

    def user_has_password(username, password):
        return username == 'user' and password == 'password'

    config.commit()
    lookup = App().registry.lookup
    c = Client(App())
    r = c.post('/login', 'username=user&password=false', status=407)
    r = c.post('/login', 'username=not_exists&password=password', status=407)
    r = c.post('/login', 'username=user&password=password')

    assert r.json == {
        'username': 'user',
    }

    claims_set = {
        'sub': 'user'
    }
    expected_token = more.jwtauth.main.encode_jwt(claims_set, settings(lookup=lookup).jwtauth)
    assert r.headers['Authorization'] == '%s %s' % ('JWT', expected_token)

    authtype, token = r.headers['Authorization'].split(' ', 1)
    claims_set_decoded = more.jwtauth.main.decode_jwt(token, settings(lookup=lookup).jwtauth)

    assert more.jwtauth.main.get_userid(claims_set_decoded, settings(lookup=lookup).jwtauth) == 'user'


def test_jwt_identity_policy():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'secret',
        }

    class Model(object):
        def __init__(self, id):
            self.id = id

    class Permission(object):
        pass

    @App.path(model=Model, path='{id}',
              variables=lambda model: {'id': model.id})
    def get_model(id):
        return Model(id)

    @App.permission_rule(model=Model, permission=Permission)
    def get_permission(identity, model, permission):
        return identity.userid == 'user'

    @App.view(model=Model, permission=Permission)
    def default(self, request):
        return "Model: %s" % self.id

    @App.identity_policy()
    def policy():
        return JWTIdentityPolicy()

    @App.verify_identity()
    def verify_identity(identity):
        assert identity is not NO_IDENTITY
        return True

    @App.view(model=HTTPForbidden)
    def make_unauthorized(self, request):
        @request.after
        def set_status_code(response):
            response.status_code = 401
        return "Unauthorized"

    config.commit()

    c = Client(App())

    response = c.get('/foo', status=401)

    headers = {'Authorization': 'JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3cm9uZyJ9.'
                                'mUHfZIsrGyUHconbskiKNIS6FkNrt3An-OwIbWBb-CA'}
    response = c.get('/foo', headers=headers, status=401)

    headers = {'Authorization': 'JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.'
                                '8jVjALlPRYpE03sMD8kuqG9D4RSih5NjiISNZ-wO3oY'}
    response = c.get('/foo', headers=headers)
    assert response.body == b'Model: foo'


def test_jwt_remember():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.path(path='{id}',
              variables=lambda model: {'id': model.id})
    class Model(object):
        def __init__(self, id):
            self.id = id

    @App.view(model=Model)
    def default(self, request):
        # will not actually do anything as it's a no-op for JWT
        # auth, but at least won't crash
        response = Response()
        morepath.remember_identity(response, request, Identity('foo'),
                                   lookup=request.lookup)
        return response

    @App.identity_policy()
    def policy():
        return JWTIdentityPolicy()

    config.commit()

    c = Client(App())

    response = c.get('/foo', status=200)
    assert response.body == b''


def test_jwt_forget():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class App(JwtApp):
        testing_config = config

    @App.path(path='{id}')
    class Model(object):
        def __init__(self, id):
            self.id = id

    @App.view(model=Model)
    def default(self, request):
        # will not actually do anything as it's a no-op for JWT
        # auth, but at least won't crash
        response = Response(content_type='text/plain')
        morepath.forget_identity(response, request, lookup=request.lookup)
        return response

    @App.identity_policy()
    def policy():
        return JWTIdentityPolicy()

    config.commit()

    c = Client(App())

    response = c.get('/foo', status=200)
    assert response.body == b''

    assert sorted(response.headers.items()) == [
        ('Content-Length', '0'),
        ('Content-Type', 'text/plain; charset=UTF-8'),
        ('WWW-Authenticate', 'JWT realm="morepath"'),
    ]

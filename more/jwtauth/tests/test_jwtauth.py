# -*- coding: utf-8 -*-
import datetime

import pytest

import morepath
from jwt import InvalidIssuerError
from more.jwtauth import JWTIdentityPolicy
from morepath import NO_IDENTITY, Identity, Response, settings
from webob.exc import HTTPProxyAuthenticationRequired
from webtest import TestApp as Client


def setup_module(module):
    morepath.disable_implicit()


def test_jwt_custom_settings():
    class App(morepath.App):
        pass

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'public_key': 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBWcJwPEAnS/k4kFgUhxNF7J0SQQhZG+nNgy+'
                          '/mXwhQ5PZIUmId1a1TjkNXiKzv6DpttBqduHbz/V0EtH+QfWy0B4BhZ5MnTyDGjcz1DQqKd'
                          'exebhzobbhSIZjpYd5aU48o9rXp/OnAnrajddpGsJ0bNf4rtMLBqFYJN6LOslAB7xTBRg=',
            'algorithm': "ES256",
            'leeway': 20
        }

    morepath.commit(App)

    app = App()
    lookup = app.lookup

    assert settings(lookup=lookup).jwtauth.algorithm == "ES256"
    assert settings(lookup=lookup).jwtauth.leeway == 20
    assert settings(
        lookup=lookup).jwtauth.public_key == 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBWcJwPEAnS/k4kFgUhxNF7J0SQQhZG+nNgy+'\
                                             '/mXwhQ5PZIUmId1a1TjkNXiKzv6DpttBqduHbz/V0EtH+QfWy0B4BhZ5MnTyDGjcz1DQqKd'\
                                             'exebhzobbhSIZjpYd5aU48o9rXp/OnAnrajddpGsJ0bNf4rtMLBqFYJN6LOslAB7xTBRg='


def test_encode_decode():
    identity_policy = JWTIdentityPolicy(master_secret='secret')
    claims_set = {
        'sub': 'user'
    }
    token = identity_policy.encode_jwt(claims_set)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert claims_set_decoded == claims_set


def test_encode_decode_with_unicode():
    identity_policy = JWTIdentityPolicy(master_secret='sëcret')
    claims_set = {
        'sub': 'user'
    }
    token = identity_policy.encode_jwt(claims_set)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert claims_set_decoded == claims_set


def test_encode_decode_with_issuer():
    identity_policy = JWTIdentityPolicy(master_secret='secret', issuer='Issuer_App')
    userid = 'user'

    extra_claims = {
        'iss': 'Invalid_Issuer_App'
    }
    claims_set = identity_policy.create_claims_set(userid, extra_claims)
    token = identity_policy.encode_jwt(claims_set)

    with pytest.raises(InvalidIssuerError):
        claims_set_decoded = identity_policy.decode_jwt(token)

    extra_claims = {
        'iss': 'Issuer_App'
    }
    claims_set = identity_policy.create_claims_set(userid, extra_claims)
    token = identity_policy.encode_jwt(claims_set)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert claims_set_decoded == claims_set


def test_create_claim_and_encode_decode_and_get_userid_and_get_extra_claims():
    identity_policy = JWTIdentityPolicy(master_secret='secret')
    userid = 'user'
    extra_claims = {
        'email': 'user@example.com',
        'role': 'admin'
    }
    claims_set = identity_policy.create_claims_set(userid, extra_claims)
    token = identity_policy.encode_jwt(claims_set)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert userid == identity_policy.get_userid(claims_set_decoded)
    assert extra_claims == identity_policy.get_extra_claims(claims_set_decoded)


def test_get_userid_without_userid():
    identity_policy = JWTIdentityPolicy(master_secret='secret')
    claims_set = {}
    token = identity_policy.encode_jwt(claims_set)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert identity_policy.get_userid(claims_set_decoded) is None


def test_create_claim_and_encode_decode_expired():
    identity_policy = JWTIdentityPolicy(
        master_secret='secret',
        expiration_delta=datetime.timedelta(seconds=-2)
    )
    userid = 'user'
    claims_set = identity_policy.create_claims_set(userid)
    token = identity_policy.encode_jwt(claims_set)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert claims_set_decoded is None


def test_create_claim_and_encode_decode_expired_but_with_leeway():
    identity_policy = JWTIdentityPolicy(
        master_secret='secret',
        expiration_delta=datetime.timedelta(seconds=-2),
        leeway=3
    )
    userid = 'user'
    claims_set = identity_policy.create_claims_set(userid)
    token = identity_policy.encode_jwt(claims_set)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert identity_policy.get_userid(claims_set_decoded) == userid


def test_login():
    class App(morepath.App):
        pass

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'secret',
            'expiration_delta': None,
        }

    @App.identity_policy()
    def get_identity_policy(settings):
        jwtauth_settings = settings.jwtauth.__dict__.copy()
        return JWTIdentityPolicy(**jwtauth_settings)

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
        def remember(response):
            identity = Identity(username)
            morepath.remember_identity(response, request, identity,
                                       lookup=request.lookup)

        return {
            'username': username,
        }

    def user_has_password(username, password):
        return username == 'user' and password == 'password'

    morepath.commit(App)
    c = Client(App())
    r = c.post('/login', 'username=user&password=false', status=407)
    r = c.post('/login', 'username=not_exists&password=password', status=407)
    r = c.post('/login', 'username=user&password=password')

    assert r.json == {
        'username': 'user',
    }

    identity_policy = JWTIdentityPolicy(
        master_secret='secret',
        expiration_delta=None
    )

    claims_set = {
        'sub': 'user'
    }
    expected_token = identity_policy.encode_jwt(claims_set)
    assert r.headers['Authorization'] == '%s %s' % ('JWT', expected_token)

    authtype, token = r.headers['Authorization'].split(' ', 1)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert identity_policy.get_userid(claims_set_decoded) == 'user'


def test_login_with_extra_claims():
    class App(morepath.App):
        pass

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'secret',
        }

    @App.identity_policy()
    def get_identity_policy(settings):
        jwtauth_settings = settings.jwtauth.__dict__.copy()
        return JWTIdentityPolicy(**jwtauth_settings)

    class Login(object):
        pass

    @App.path(model=Login, path='login')
    def get_login():
        return Login()

    @App.json(model=Login, request_method='POST')
    def login(self, request):
        username = request.POST['username']
        password = request.POST['password']
        fullname = request.POST['fullname']
        email = request.POST['email']
        role = request.POST['role']

        if not user_has_password(username, password):
            raise HTTPProxyAuthenticationRequired('Invalid username/password')

        @request.after
        def remember(response):
            identity = Identity(username, fullname=fullname, email=email, role=role)
            morepath.remember_identity(response, request, identity,
                                       lookup=request.lookup)

        return {
            'username': username,
            'fullname': fullname,
            'email': email,
            'role': role
        }

    def user_has_password(username, password):
        return username == 'user' and password == 'password'

    morepath.commit(App)
    c = Client(App())
    params = {
        'username': 'not_exist',
        'password': 'password',
        'fullname': 'Harry Potter',
        'email': 'harry@potter.com',
        'role': 'wizard'
    }
    r = c.post('/login', params, status=407)
    params = {
        'username': 'user',
        'password': 'password',
        'fullname': 'Harry Potter',
        'email': 'harry@potter.com',
        'role': 'wizard'
    }
    r = c.post('/login', params)

    assert r.json == {
        'username': 'user',
        'fullname': 'Harry Potter',
        'email': 'harry@potter.com',
        'role': 'wizard'
    }

    identity_policy = JWTIdentityPolicy(
        master_secret='secret',
    )

    authtype, token = r.headers['Authorization'].split(' ', 1)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert identity_policy.get_userid(claims_set_decoded) == 'user'

    extra_claims = {
        'fullname': 'Harry Potter',
        'email': 'harry@potter.com',
        'role': 'wizard'
    }
    assert identity_policy.get_extra_claims(claims_set_decoded) == extra_claims


def test_jwt_identity_policy():
    class App(morepath.App):
        pass

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

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'secret',
        }

    @App.identity_policy()
    def get_identity_policy(settings):
        jwtauth_settings = settings.jwtauth.__dict__.copy()
        return JWTIdentityPolicy(**jwtauth_settings)

    @App.verify_identity()
    def verify_identity(identity):
        assert identity is not NO_IDENTITY
        return True

    morepath.commit(App)

    c = Client(App())

    identity_policy = JWTIdentityPolicy(
        master_secret='secret',
    )

    response = c.get('/foo', status=403)

    claims_set = {
        'sub': 'wrong_user'
    }
    token = identity_policy.encode_jwt(claims_set)
    headers = {'Authorization': 'JWT ' + token}
    response = c.get('/foo', headers=headers, status=403)

    claims_set = {
        'sub': 'user'
    }
    token = identity_policy.encode_jwt(claims_set)
    headers = {'Authorization': 'JWT ' + token}
    response = c.get('/foo', headers=headers)
    assert response.body == b'Model: foo'

    # extra claims
    claims_set = {
        'sub': 'user',
        'email': 'harry@potter.com',
    }
    token = identity_policy.encode_jwt(claims_set)
    headers = {'Authorization': 'JWT ' + token}
    response = c.get('/foo', headers=headers)
    assert response.body == b'Model: foo'


def test_jwt_identity_policy_errors():
    class App(morepath.App):
        pass

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

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': u'sëcret',
            'leeway': None
        }

    @App.identity_policy()
    def get_identity_policy(settings):
        jwtauth_settings = settings.jwtauth.__dict__.copy()
        return JWTIdentityPolicy(**jwtauth_settings)

    @App.verify_identity()
    def verify_identity(identity):
        assert identity is not NO_IDENTITY
        return True

    morepath.commit(App)

    c = Client(App())

    identity_policy = JWTIdentityPolicy(
        master_secret=u'sëcret'
    )

    response = c.get('/foo', status=403)

    headers = {'Authorization': 'Something'}
    response = c.get('/foo', headers=headers, status=403)

    headers = {'Authorization': 'JWT ' + 'nonsense'}
    response = c.get('/foo', headers=headers, status=403)

    # no userid
    claims_set = {
        'sub': None
    }
    token = identity_policy.encode_jwt(claims_set)
    headers = {'Authorization': 'JWT ' + token}
    response = c.get('/foo', headers=headers, status=403)

    claims_set = {
        'sub': 'user'
    }
    token = identity_policy.encode_jwt(claims_set)

    headers = {'Authorization': 'OtherAuthType ' + token}
    response = c.get('/foo', headers=headers, status=403)

    headers = {'Authorization': 'JWT ' + token}
    response = c.get('/foo', headers=headers)
    assert response.body == b'Model: foo'


def test_jwt_remember():
    class App(morepath.App):
        pass

    @App.path(path='{id}',
              variables=lambda model: {'id': model.id})
    class Model(object):
        def __init__(self, id):
            self.id = id

    @App.view(model=Model)
    def default(self, request):
        response = Response()
        morepath.remember_identity(response, request, Identity('foo'),
                                   lookup=request.lookup)
        return response

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            'master_secret': 'secret',
        }

    @App.identity_policy()
    def get_identity_policy(settings):
        jwtauth_settings = settings.jwtauth.__dict__.copy()
        return JWTIdentityPolicy(**jwtauth_settings)

    morepath.commit(App)

    c = Client(App())

    response = c.get('/foo', status=200)
    assert response.body == b''
    assert isinstance(response.headers['Authorization'], str)
    assert response.headers['Authorization'][:7] == 'JWT eyJ'


def test_jwt_forget():
    class App(morepath.App):
        pass

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
    def get_identity_policy():
        return JWTIdentityPolicy()

    morepath.commit(App)

    c = Client(App())

    response = c.get('/foo', status=200)
    assert response.body == b''

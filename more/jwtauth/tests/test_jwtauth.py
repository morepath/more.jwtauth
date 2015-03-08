# -*- coding: utf-8 -*-
import morepath
from morepath.request import Response
from morepath import settings
from morepath.security import (Identity, NO_IDENTITY)

from more.jwtauth import JwtApp
from more.jwtauth.main import JWTIdentityPolicy
import more.jwtauth
import base64
from webob.exc import HTTPForbidden
from webtest import TestApp as Client
import pytest


def setup_module(module):
    morepath.disable_implicit()


def test_jwt_default_settings():
    morepath.enable_implicit()
    config = morepath.setup()

    class app(JwtApp):
        testing_config = config
    config.commit()

    assert settings().jwtauth.algorithm == "HS256"
    assert settings().jwtauth.auth_header_prefix == "JWT"
    assert settings().jwtauth.master_secret is None


def test_jwt_identity_policy():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class app(JwtApp):
        testing_config = config

    class Model(object):
        def __init__(self, id):
            self.id = id

    class Permission(object):
        pass

    @app.path(model=Model, path='{id}',
              variables=lambda model: {'id': model.id})
    def get_model(id):
        return Model(id)

    @app.permission_rule(model=Model, permission=Permission)
    def get_permission(identity, model, permission):
        return identity.userid == 'user' and identity.password == 'secret'

    @app.view(model=Model, permission=Permission)
    def default(self, request):
        return "Model: %s" % self.id

    @app.identity_policy()
    def policy():
        return JWTIdentityPolicy()

    @app.verify_identity()
    def verify_identity(identity):
        assert identity is not NO_IDENTITY
        return True

    @app.view(model=HTTPForbidden)
    def make_unauthorized(self, request):
        @request.after
        def set_status_code(response):
            response.status_code = 401
        return "Unauthorized"

    config.commit()

    c = Client(app())

    response = c.get('/foo', status=401)

    headers = {'Authorization': 'JWT ' +
               str(base64.b64encode(b'user:wrong').decode())}
    response = c.get('/foo', headers=headers, status=401)

    headers = {'Authorization': 'JWT ' +
               str(base64.b64encode(b'user:secret').decode())}
    response = c.get('/foo', headers=headers)
    assert response.body == b'Model: foo'


def test_jwt_identity_policy_errors():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class app(JwtApp):
        testing_config = config

    class Model(object):
        def __init__(self, id):
            self.id = id

    class Permission(object):
        pass

    @app.path(model=Model, path='{id}',
              variables=lambda model: {'id': model.id})
    def get_model(id):
        return Model(id)

    @app.permission_rule(model=Model, permission=Permission)
    def get_permission(identity, model, permission):
        return identity.userid == 'user' and identity.password == u'sëcret'

    @app.view(model=Model, permission=Permission)
    def default(self, request):
        return "Model: %s" % self.id

    @app.identity_policy()
    def policy():
        return JWTIdentityPolicy()

    @app.verify_identity()
    def verify_identity(identity):
        return True

    config.commit()

    c = Client(app())

    response = c.get('/foo', status=403)

    headers = {'Authorization': 'Something'}
    response = c.get('/foo', headers=headers, status=403)

    headers = {'Authorization': 'Something other'}
    response = c.get('/foo', headers=headers, status=403)

    headers = {'Authorization': 'JWT ' + 'nonsense'}
    response = c.get('/foo', headers=headers, status=403)

    headers = {'Authorization': 'JWT ' + 'nonsense1'}
    response = c.get('/foo', headers=headers, status=403)

    # fallback to utf8
    headers = {
        'Authorization': 'JWT ' + str(base64.b64encode(
            u'user:sëcret'.encode('utf8')).decode())}
    response = c.get('/foo', headers=headers)
    assert response.body == b'Model: foo'

    # fallback to latin1
    headers = {
        'Authorization': 'JWT ' + str(base64.b64encode(
            u'user:sëcret'.encode('latin1')).decode())}
    response = c.get('/foo', headers=headers)
    assert response.body == b'Model: foo'

    # unknown encoding
    headers = {
        'Authorization': 'JWT ' + str(base64.b64encode(
            u'user:sëcret'.encode('cp500')).decode())}
    response = c.get('/foo', headers=headers, status=403)

    headers = {
        'Authorization': 'JWT ' + str(base64.b64encode(
            u'usersëcret'.encode('utf8')).decode())}
    response = c.get('/foo', headers=headers, status=403)

    headers = {
        'Authorization': 'JWT ' + str(base64.b64encode(
            u'user:sëcret:'.encode('utf8')).decode())}
    response = c.get('/foo', headers=headers, status=403)


def test_jwt_remember():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class app(JwtApp):
        testing_config = config

    @app.path(path='{id}',
              variables=lambda model: {'id': model.id})
    class Model(object):
        def __init__(self, id):
            self.id = id

    @app.view(model=Model)
    def default(self, request):
        # will not actually do anything as it's a no-op for basic
        # auth, but at least won't crash
        response = Response()
        morepath.remember_identity(response, request, Identity('foo'),
                                  lookup=request.lookup)
        return response

    @app.identity_policy()
    def policy():
        return JWTIdentityPolicy()

    config.commit()

    c = Client(app())

    response = c.get('/foo', status=200)
    assert response.body == b''


def test_jwt_forget():
    config = morepath.setup()
    config.scan(more.jwtauth)

    class app(JwtApp):
        testing_config = config

    @app.path(path='{id}')
    class Model(object):
        def __init__(self, id):
            self.id = id

    @app.view(model=Model)
    def default(self, request):
        # will not actually do anything as it's a no-op for basic
        # auth, but at least won't crash
        response = Response(content_type='text/plain')
        morepath.forget_identity(response, request, lookup=request.lookup)
        return response

    @app.identity_policy()
    def policy():
        return JWTIdentityPolicy()

    config.commit()

    c = Client(app())

    response = c.get('/foo', status=200)
    assert response.body == b''

    assert sorted(response.headers.items()) == [
        ('Content-Length', '0'),
        ('Content-Type', 'text/plain; charset=UTF-8'),
        ('WWW-Authenticate', 'JWT'),
    ]




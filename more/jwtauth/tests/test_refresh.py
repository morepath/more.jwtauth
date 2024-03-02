from calendar import timegm
from datetime import datetime, timedelta

import morepath
import pytest
from morepath import Identity
from webtest import TestApp as Client

from more.jwtauth import (
    DecodeError,
    ExpiredSignatureError,
    InvalidTokenError,
    JWTIdentityPolicy,
    MissingRequiredClaimError,
    verify_refresh_request,
)
from more.jwtauth.utils import handler


def test_handler():
    assert handler(None) is None

    refresh_nonce_handler = handler(
        "more.jwtauth.tests.handler.refresh_nonce_handler"
    )
    assert refresh_nonce_handler(None, "user") == "__user__"

    with pytest.raises(ImportError) as excinfo:
        handler("refresh_nonce_handler")
    assert "Could not import the name: refresh_nonce_handler" in str(
        excinfo.value
    )


def test_create_claims_with_refresh_until_and_nonce():
    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"

    identity_policy = JWTIdentityPolicy(
        master_secret="secret",
        allow_refresh=True,
        refresh_delta=timedelta(seconds=2),
        refresh_nonce_handler=refresh_nonce_handler,
    )

    userid = "user"
    claims_set = identity_policy.create_claims_set(None, userid)

    now = timegm(datetime.utcnow().utctimetuple())

    assert claims_set["refresh_until"] >= now + 1
    assert claims_set["refresh_until"] <= now + 3
    assert claims_set["nonce"] == "__user__"


def test_refresh_token():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.identity_policy()
    def get_identity_policy(settings):
        jwtauth_settings = settings.jwtauth.__dict__.copy()
        return JWTIdentityPolicy(**jwtauth_settings)

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        userid = verify_refresh_request(request)

        @request.after
        def remember(response):
            identity = Identity(userid)
            request.app.remember_identity(response, request, identity)

        return {"userid": userid}

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"
    refresh_delta = 3600

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            "master_secret": "secret",
            "allow_refresh": True,
            "refresh_delta": refresh_delta,
            "refresh_nonce_handler": refresh_nonce_handler,
        }

    morepath.commit(App)
    app = App()

    settings = app.settings.jwtauth.__dict__.copy()
    identity_policy = JWTIdentityPolicy(**settings)

    now = timegm(datetime.utcnow().utctimetuple())

    claims_set = {
        "sub": "user",
        "refresh_until": now + refresh_delta,
        "nonce": "__user__",
    }

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    c = Client(app)

    r = c.get("/refresh", headers=headers)

    assert r.json == {
        "userid": "user",
    }

    authtype, token = r.headers["Authorization"].split(" ", 1)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert identity_policy.get_userid(claims_set_decoded) == "user"


def test_refresh_nonce_handler_set_by_decorator():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.identity_policy()
    def get_identity_policy(settings):
        jwtauth_settings = settings.jwtauth.__dict__.copy()
        return JWTIdentityPolicy(**jwtauth_settings)

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        userid = verify_refresh_request(request)

        @request.after
        def remember(response):
            identity = Identity(userid)
            request.app.remember_identity(response, request, identity)

        return {"userid": userid}

    refresh_delta = 3600

    @App.setting(section="jwtauth", name="refresh_nonce_handler")
    def get_handler():
        def refresh_nonce_handler(request, userid):
            return "__" + userid + "__"

        return refresh_nonce_handler

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            "master_secret": "secret",
            "allow_refresh": True,
            "refresh_delta": refresh_delta,
        }

    morepath.commit(App)
    app = App()
    c = Client(app)

    settings = app.settings.jwtauth.__dict__.copy()
    identity_policy = JWTIdentityPolicy(**settings)

    now = timegm(datetime.utcnow().utctimetuple())

    claims_set = {
        "sub": "user",
        "refresh_until": now + refresh_delta,
        "nonce": "__user__",
    }

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    r = c.get("/refresh", headers=headers)

    assert r.json == {
        "userid": "user",
    }

    authtype, token = r.headers["Authorization"].split(" ", 1)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert identity_policy.get_userid(claims_set_decoded) == "user"


def test_refresh_token_with_extra_claims():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.identity_policy()
    def get_identity_policy(settings):
        jwtauth_settings = settings.jwtauth.__dict__.copy()
        return JWTIdentityPolicy(**jwtauth_settings)

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        userid = verify_refresh_request(request)
        updated_extra_claims = {
            "fullname": "Harry Potter",
            "email": "harry@potter.com",
            "role": "father",
        }

        @request.after
        def remember(response):
            identity = Identity(userid, **updated_extra_claims)
            request.app.remember_identity(response, request, identity)

        return {
            "userid": "user",
            "fullname": "Harry Potter",
            "email": "harry@potter.com",
            "role": "father",
        }

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"
    refresh_delta = 3600
    settings = {
        "master_secret": "secret",
        "allow_refresh": True,
        "refresh_delta": refresh_delta,
        "refresh_nonce_handler": refresh_nonce_handler,
    }

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return settings

    identity_policy = JWTIdentityPolicy(**settings)

    now = timegm(datetime.utcnow().utctimetuple())

    claims_set = {
        "sub": "user",
        "refresh_until": now + refresh_delta,
        "nonce": "__user__",
        "fullname": "Harry Potter",
        "email": "harry@potter.com",
        "role": "wizard",
    }

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    morepath.commit(App)
    app = App()
    c = Client(app)

    r = c.get("/refresh", headers=headers)

    assert r.json == {
        "userid": "user",
        "fullname": "Harry Potter",
        "email": "harry@potter.com",
        "role": "father",
    }

    authtype, token = r.headers["Authorization"].split(" ", 1)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert identity_policy.get_userid(claims_set_decoded) == "user"

    extra_claims = {
        "fullname": "Harry Potter",
        "email": "harry@potter.com",
        "role": "father",
    }
    assert identity_policy.get_extra_claims(claims_set_decoded) == extra_claims


def test_refresh_delta_expired():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        verify_refresh_request(request)

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"
    refresh_delta = timedelta(seconds=-2)
    settings = {
        "master_secret": "secret",
        "allow_refresh": True,
        "refresh_delta": refresh_delta,
        "refresh_nonce_handler": refresh_nonce_handler,
    }

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return settings

    identity_policy = JWTIdentityPolicy(**settings)

    refresh_until = timegm((datetime.utcnow() + refresh_delta).utctimetuple())

    claims_set = {
        "sub": "user",
        "refresh_until": refresh_until,
        "nonce": "__user__",
    }

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    morepath.commit(App)
    c = Client(App())

    with pytest.raises(ExpiredSignatureError) as excinfo:
        c.get("/refresh", headers=headers)
    assert "Refresh nonce has expired" in str(excinfo.value)


def test_refresh_not_allowed():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        verify_refresh_request(request)

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"
    refresh_delta = timedelta(seconds=3600)
    settings = {
        "master_secret": "secret",
        "allow_refresh": False,
        "refresh_delta": refresh_delta,
        "refresh_nonce_handler": refresh_nonce_handler,
    }

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return settings

    identity_policy = JWTIdentityPolicy(**settings)

    refresh_until = timegm((datetime.utcnow() + refresh_delta).utctimetuple())

    claims_set = {
        "sub": "user",
        "refresh_until": refresh_until,
        "nonce": "__user__",
    }

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    morepath.commit(App)
    c = Client(App())

    with pytest.raises(InvalidTokenError) as excinfo:
        c.get("/refresh", headers=headers)
    assert "Token refresh is disabled" in str(excinfo.value)


def test_refresh_delta_expired_but_with_leeway():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.identity_policy()
    def get_identity_policy(settings):
        jwtauth_settings = settings.jwtauth.__dict__.copy()
        return JWTIdentityPolicy(**jwtauth_settings)

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        userid = verify_refresh_request(request)

        @request.after
        def remember(response):
            identity = Identity(userid)
            request.app.remember_identity(response, request, identity)

        return {"userid": userid}

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"
    settings = {
        "master_secret": "secret",
        "leeway": timedelta(seconds=3),
        "allow_refresh": True,
        "refresh_delta": -2,
        "refresh_nonce_handler": refresh_nonce_handler,
    }

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return settings

    identity_policy = JWTIdentityPolicy(**settings)

    now = timegm(datetime.utcnow().utctimetuple())

    claims_set = {"sub": "user", "refresh_until": now - 2, "nonce": "__user__"}

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    morepath.commit(App)
    c = Client(App())

    r = c.get("/refresh", headers=headers)

    assert r.json == {
        "userid": "user",
    }

    authtype, token = r.headers["Authorization"].split(" ", 1)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert identity_policy.get_userid(claims_set_decoded) == "user"


def test_expiration_delta_expired_with_verify_expiration_on_refresh():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        verify_refresh_request(request)

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"
    expiration_delta = timedelta(seconds=-3)
    refresh_delta = timedelta(seconds=3)
    settings = {
        "master_secret": "secret",
        "expiration_delta": expiration_delta,
        "allow_refresh": True,
        "refresh_delta": refresh_delta,
        "refresh_nonce_handler": refresh_nonce_handler,
        "verify_expiration_on_refresh": True,
    }

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return settings

    identity_policy = JWTIdentityPolicy(**settings)

    exp = timegm((datetime.utcnow() + expiration_delta).utctimetuple())
    refresh_until = timegm((datetime.utcnow() + refresh_delta).utctimetuple())

    claims_set = {
        "sub": "user",
        "exp": exp,
        "refresh_until": refresh_until,
        "nonce": "__user__",
    }

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    morepath.commit(App)
    c = Client(App())

    with pytest.raises(ExpiredSignatureError) as excinfo:
        c.get("/refresh", headers=headers)
    assert "Token has expired" in str(excinfo.value)


def test_expiration_delta_expired_without_verify_expiration_on_refresh():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.identity_policy()
    def get_identity_policy(settings):
        jwtauth_settings = settings.jwtauth.__dict__.copy()
        return JWTIdentityPolicy(**jwtauth_settings)

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        userid = verify_refresh_request(request)

        @request.after
        def remember(response):
            identity = Identity(userid)
            request.app.remember_identity(response, request, identity)

        return {"userid": userid}

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"
    expiration_delta = -3
    refresh_delta = 3
    settings = {
        "master_secret": "secret",
        "expiration_delta": expiration_delta,
        "leeway": timedelta(seconds=3),
        "allow_refresh": True,
        "refresh_delta": refresh_delta,
        "refresh_nonce_handler": refresh_nonce_handler,
    }

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return settings

    identity_policy = JWTIdentityPolicy(**settings)

    now = timegm(datetime.utcnow().utctimetuple())

    claims_set = {
        "sub": "user",
        "exp": now + expiration_delta,
        "refresh_until": now + refresh_delta,
        "nonce": "__user__",
    }

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    morepath.commit(App)
    c = Client(App())

    r = c.get("/refresh", headers=headers)

    assert r.json == {
        "userid": "user",
    }

    authtype, token = r.headers["Authorization"].split(" ", 1)
    claims_set_decoded = identity_policy.decode_jwt(
        token, verify_expiration=False
    )

    assert identity_policy.get_userid(claims_set_decoded) == "user"


def test_refresh_without_refresh_nonce_handler_setting():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.identity_policy()
    def get_identity_policy(settings):
        jwtauth_settings = settings.jwtauth.__dict__.copy()
        return JWTIdentityPolicy(**jwtauth_settings)

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        userid = verify_refresh_request(request)

        @request.after
        def remember(response):
            identity = Identity(userid)
            request.app.remember_identity(response, request, identity)

        return {"userid": userid}

    settings = {
        "master_secret": "secret",
        "allow_refresh": True,
        "refresh_delta": 3,
    }

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return settings

    identity_policy = JWTIdentityPolicy(**settings)

    now = timegm(datetime.utcnow().utctimetuple())

    claims_set = {
        "sub": "user",
        "refresh_until": now + 3,
    }

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    morepath.commit(App)
    c = Client(App())

    r = c.get("/refresh", headers=headers)

    assert r.json == {
        "userid": "user",
    }

    authtype, token = r.headers["Authorization"].split(" ", 1)
    claims_set_decoded = identity_policy.decode_jwt(token)

    assert identity_policy.get_userid(claims_set_decoded) == "user"


def test_refresh_without_token():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        verify_refresh_request(request)

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            "master_secret": "secret",
            "allow_refresh": True,
            "refresh_delta": 3,
            "refresh_nonce_handler": refresh_nonce_handler,
        }

    morepath.commit(App)
    c = Client(App())

    with pytest.raises(InvalidTokenError) as excinfo:
        c.get("/refresh")
    assert "Token not found" in str(excinfo.value)


def test_refresh_with_invalid_token():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        verify_refresh_request(request)

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return {
            "master_secret": "secret",
            "allow_refresh": True,
            "refresh_delta": 3,
            "refresh_nonce_handler": refresh_nonce_handler,
        }

    token = "Invalid Token"
    headers = {"Authorization": "JWT " + token}

    morepath.commit(App)
    c = Client(App())

    with pytest.raises(DecodeError) as excinfo:
        c.get("/refresh", headers=headers)
    assert "Token could not be decoded" in str(excinfo.value)


def test_refresh_with_invalid_refresh_nonce():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        verify_refresh_request(request)

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"
    settings = {
        "master_secret": "secret",
        "allow_refresh": True,
        "refresh_delta": 3,
        "refresh_nonce_handler": refresh_nonce_handler,
    }

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return settings

    identity_policy = JWTIdentityPolicy(**settings)

    now = timegm(datetime.utcnow().utctimetuple())

    claims_set = {
        "sub": "user",
        "refresh_until": now + 3,
        "nonce": "__invalid__",
    }

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    morepath.commit(App)
    c = Client(App())

    with pytest.raises(InvalidTokenError) as excinfo:
        c.get("/refresh", headers=headers)
    assert "Refresh nonce is not valid" in str(excinfo.value)


def test_refresh_with_missing_userid_claim():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        verify_refresh_request(request)

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"
    settings = {
        "master_secret": "secret",
        "allow_refresh": True,
        "refresh_delta": 3,
        "refresh_nonce_handler": refresh_nonce_handler,
    }

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return settings

    identity_policy = JWTIdentityPolicy(**settings)

    now = timegm(datetime.utcnow().utctimetuple())

    claims_set = {"refresh_until": now + 3, "nonce": "__user__"}

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    morepath.commit(App)
    c = Client(App())

    with pytest.raises(MissingRequiredClaimError) as excinfo:
        c.get("/refresh", headers=headers)
    assert 'Token is missing the "sub" claim' in str(excinfo.value)


def test_refresh_with_missing_refresh_until_claim():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        verify_refresh_request(request)

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"
    settings = {
        "master_secret": "secret",
        "allow_refresh": True,
        "refresh_delta": 3,
        "refresh_nonce_handler": refresh_nonce_handler,
    }

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return settings

    identity_policy = JWTIdentityPolicy(**settings)

    claims_set = {"sub": "user", "nonce": "__user__"}

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    morepath.commit(App)
    c = Client(App())

    with pytest.raises(MissingRequiredClaimError) as excinfo:
        c.get("/refresh", headers=headers)
    assert 'Token is missing the "refresh_until" claim' in str(excinfo.value)


def test_refresh_with_missing_nonce_claim():
    class App(morepath.App):
        pass

    class Refresh:
        pass

    @App.path(model=Refresh, path="refresh")
    def get_refresh():
        return Refresh()

    @App.json(model=Refresh)
    def refresh(self, request):
        verify_refresh_request(request)

    refresh_nonce_handler = "more.jwtauth.tests.handler.refresh_nonce_handler"
    settings = {
        "master_secret": "secret",
        "allow_refresh": True,
        "refresh_delta": 3,
        "refresh_nonce_handler": refresh_nonce_handler,
    }

    @App.setting_section(section="jwtauth")
    def get_jwtauth_settings():
        return settings

    identity_policy = JWTIdentityPolicy(**settings)

    now = timegm(datetime.utcnow().utctimetuple())

    claims_set = {"sub": "user", "refresh_until": now + 3}

    token = identity_policy.encode_jwt(claims_set)
    headers = {"Authorization": "JWT " + token}

    morepath.commit(App)
    c = Client(App())

    with pytest.raises(MissingRequiredClaimError) as excinfo:
        c.get("/refresh", headers=headers)
    assert 'Token is missing the "nonce" claim' in str(excinfo.value)

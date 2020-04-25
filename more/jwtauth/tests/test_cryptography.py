import pytest

from more.jwtauth import JWTIdentityPolicy

try:
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa

    has_crypto = True
except ImportError:  # pragma: no cover
    has_crypto = False


def relative(filepath):
    import os

    return os.path.join(os.path.dirname(__file__), filepath)


@pytest.mark.skipif(
    not has_crypto, reason="Not supported without cryptography library"
)
class TestCryptographyAlgorithms:
    def test_encode_decode_with_es256_as_bytes(self):
        with open(relative("keys/testkey_ec")) as key_priv_file:
            private_key = key_priv_file.read()
        with open(relative("keys/testkey_ec.pub")) as key_pub_file:
            public_key = key_pub_file.read()

        identity_policy = JWTIdentityPolicy(
            algorithm="ES256", private_key=private_key, public_key=public_key
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_es256(self):
        identity_policy = JWTIdentityPolicy(
            algorithm="ES256",
            private_key_file=relative("keys/testkey_ec"),
            public_key_file=relative("keys/testkey_ec.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_es384(self):
        identity_policy = JWTIdentityPolicy(
            algorithm="ES384",
            private_key_file=relative("keys/testkey_ec"),
            public_key_file=relative("keys/testkey_ec.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_es512(self):
        identity_policy = JWTIdentityPolicy(
            algorithm="ES512",
            private_key_file=relative("keys/testkey_ec"),
            public_key_file=relative("keys/testkey_ec.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_ps256(self):
        identity_policy = JWTIdentityPolicy(
            algorithm="PS256",
            private_key_file=relative("keys/testkey_rsa"),
            public_key_file=relative("keys/testkey_rsa.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_ps384(self):
        identity_policy = JWTIdentityPolicy(
            algorithm="PS384",
            private_key_file=relative("keys/testkey_rsa"),
            public_key_file=relative("keys/testkey_rsa.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_ps512(self):
        identity_policy = JWTIdentityPolicy(
            algorithm="PS512",
            private_key_file=relative("keys/testkey_rsa"),
            public_key_file=relative("keys/testkey_rsa.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_rs256(self):
        identity_policy = JWTIdentityPolicy(
            algorithm="RS256",
            private_key_file=relative("keys/testkey_rsa"),
            public_key_file=relative("keys/testkey_rsa.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_rs384(self):
        identity_policy = JWTIdentityPolicy(
            algorithm="RS384",
            private_key_file=relative("keys/testkey_rsa"),
            public_key_file=relative("keys/testkey_rsa.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_rs512(self):
        identity_policy = JWTIdentityPolicy(
            algorithm="RS512",
            private_key_file=relative("keys/testkey_rsa"),
            public_key_file=relative("keys/testkey_rsa.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

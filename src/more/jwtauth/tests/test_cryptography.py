from importlib.util import find_spec

import pytest

from more.jwtauth import JWTIdentityPolicy

has_crypto = find_spec("cryptography") is not None


def relative(filepath: str) -> str:
    import os

    return os.path.join(os.path.dirname(__file__), filepath)


@pytest.mark.skipif(not has_crypto, reason="Not supported without cryptography library")
class TestCryptographyAlgorithms:
    def test_encode_decode_with_es256_as_bytes(self) -> None:
        with open(relative("keys/testkey_ec256")) as key_priv_file:
            private_key = key_priv_file.read()
        with open(relative("keys/testkey_ec256.pub")) as key_pub_file:
            public_key = key_pub_file.read()

        identity_policy = JWTIdentityPolicy(
            algorithm="ES256", private_key=private_key, public_key=public_key
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_es256(self) -> None:
        identity_policy = JWTIdentityPolicy(
            algorithm="ES256",
            private_key_file=relative("keys/testkey_ec256"),
            public_key_file=relative("keys/testkey_ec256.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_es384(self) -> None:
        identity_policy = JWTIdentityPolicy(
            algorithm="ES384",
            private_key_file=relative("keys/testkey_ec384"),
            public_key_file=relative("keys/testkey_ec384.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_es512(self) -> None:
        identity_policy = JWTIdentityPolicy(
            algorithm="ES512",
            private_key_file=relative("keys/testkey_ec512"),
            public_key_file=relative("keys/testkey_ec512.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    @pytest.mark.parametrize(
        ("algorithm", "key_type"),
        [
            ("ES256K", "secp256k1"),
            ("EdDSA", "ed25519"),
            ("EdDSA", "ed448"),
        ],
    )
    def test_encode_decode_with_es256k_and_eddsa(
        self, algorithm: str, key_type: str
    ) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519

        private_key: (
            ec.EllipticCurvePrivateKey
            | ed25519.Ed25519PrivateKey
            | ed448.Ed448PrivateKey
        )
        if key_type == "secp256k1":
            private_key = ec.generate_private_key(ec.SECP256K1())
        elif key_type == "ed25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            private_key = ed448.Ed448PrivateKey.generate()

        private_key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        public_key_pem = (
            private_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        identity_policy = JWTIdentityPolicy(
            algorithm=algorithm,
            private_key=private_key_pem,
            public_key=public_key_pem,
        )
        claims_set = {"sub": key_type}
        token = identity_policy.encode_jwt(claims_set)

        assert identity_policy.decode_jwt(token) == claims_set

    def test_encode_decode_with_ps256(self) -> None:
        identity_policy = JWTIdentityPolicy(
            algorithm="PS256",
            private_key_file=relative("keys/testkey_rsa"),
            public_key_file=relative("keys/testkey_rsa.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_ps384(self) -> None:
        identity_policy = JWTIdentityPolicy(
            algorithm="PS384",
            private_key_file=relative("keys/testkey_rsa"),
            public_key_file=relative("keys/testkey_rsa.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_ps512(self) -> None:
        identity_policy = JWTIdentityPolicy(
            algorithm="PS512",
            private_key_file=relative("keys/testkey_rsa"),
            public_key_file=relative("keys/testkey_rsa.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_rs256(self) -> None:
        identity_policy = JWTIdentityPolicy(
            algorithm="RS256",
            private_key_file=relative("keys/testkey_rsa"),
            public_key_file=relative("keys/testkey_rsa.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_rs384(self) -> None:
        identity_policy = JWTIdentityPolicy(
            algorithm="RS384",
            private_key_file=relative("keys/testkey_rsa"),
            public_key_file=relative("keys/testkey_rsa.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

    def test_encode_decode_with_rs512(self) -> None:
        identity_policy = JWTIdentityPolicy(
            algorithm="RS512",
            private_key_file=relative("keys/testkey_rsa"),
            public_key_file=relative("keys/testkey_rsa.pub"),
        )
        claims_set = {"sub": "user"}
        token = identity_policy.encode_jwt(claims_set)
        claims_set_decoded = identity_policy.decode_jwt(token)

        assert claims_set_decoded == claims_set

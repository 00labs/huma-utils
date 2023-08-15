import datetime

import fastapi
import jwt
import pytest
from Crypto.PublicKey import RSA

from huma_utils import auth_utils, constants, datetime_utils
from huma_utils.test_helpers import address_helpers


def describe_verify_wallet_ownership() -> None:
    @pytest.fixture(scope="session")
    def rsa_key() -> RSA.RsaKey:
        return RSA.generate(2048)

    @pytest.fixture
    def wallet_address() -> str:
        return address_helpers.fake_hex_address()

    @pytest.fixture
    def chain_id() -> str:
        return "1"

    @pytest.fixture
    def claim_sub(wallet_address: str, chain_id: str) -> str:
        return f"{wallet_address}:{chain_id}"

    @pytest.fixture
    def token_expiration_time() -> datetime.datetime:
        return datetime_utils.tz_aware_utc_now() + datetime.timedelta(days=3)

    @pytest.fixture
    def token_issuer() -> str:
        return constants.HUMA_FINANCE_DOMAIN_NAME

    @pytest.fixture
    def id_token(
        claim_sub: str,
        token_expiration_time: datetime.datetime,
        token_issuer: str,
        rsa_key: RSA.RsaKey,
    ) -> str:
        claim = auth_utils.JWTClaim(
            sub=claim_sub,
            exp=token_expiration_time,
            iat=datetime_utils.tz_aware_utc_now(),
            iss=token_issuer,
        )
        return jwt.encode(
            payload=claim.dict(),
            key=rsa_key.export_key(),
            algorithm="RS256",
        )

    @pytest.fixture
    def id_token_cookie(id_token: str) -> str:
        return f"id_token={id_token}"

    @pytest.fixture
    def request_with_cookie(id_token_cookie: str) -> fastapi.Request:
        return fastapi.Request(
            scope={
                "type": "http",
                "headers": [("cookie".encode(), id_token_cookie.encode())],
            }
        )

    def it_performs_the_verification(
        request_with_cookie: fastapi.Request,
        wallet_address: str,
        chain_id: str,
        rsa_key: RSA.RsaKey,
    ) -> None:
        auth_utils.verify_wallet_ownership(
            request=request_with_cookie,
            jwt_public_key=rsa_key.public_key().export_key().decode(),
            wallet_address=wallet_address,
            chain_id=chain_id,
        )

    def if_the_cookie_is_missing() -> None:
        @pytest.fixture
        def id_token_cookie(id_token: str) -> str:
            return ""

        def it_throws_error(
            request_with_cookie: fastapi.Request,
            wallet_address: str,
            chain_id: str,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.IdTokenNotFoundException):
                auth_utils.verify_wallet_ownership(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                    wallet_address=wallet_address,
                    chain_id=chain_id,
                )

    def if_the_jwt_is_tampered_with() -> None:
        @pytest.fixture
        def id_token_cookie(
            wallet_address: str,
            id_token: str,
            token_expiration_time: datetime.datetime,
            token_issuer: str,
            rsa_key: RSA.RsaKey,
        ) -> str:
            header, _, sig = id_token.split(".")
            claim = auth_utils.JWTClaim(
                sub=f"{wallet_address}:2",
                exp=token_expiration_time,
                iat=datetime_utils.tz_aware_utc_now(),
                iss=token_issuer,
            )
            new_token = jwt.encode(
                payload=claim.dict(),
                key=rsa_key.export_key(),
                algorithm="RS256",
            )
            _, new_token_payload, _ = new_token.split(".")
            # Replaces the claim with an invalid one to simulate the jwt being tampered with.
            return f"id_token={'.'.join([header, new_token_payload, sig])}"

        def it_throws_error(
            request_with_cookie: fastapi.Request,
            wallet_address: str,
            chain_id: str,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.InvalidIdTokenException):
                auth_utils.verify_wallet_ownership(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                    wallet_address=wallet_address,
                    chain_id=chain_id,
                )

    def if_the_claim_is_malformed() -> None:
        @pytest.fixture
        def id_token(
            claim_sub: str,
            token_expiration_time: datetime.datetime,
            rsa_key: RSA.RsaKey,
        ) -> str:
            return jwt.encode(
                payload={
                    "sub": claim_sub,
                    "exp": token_expiration_time,
                    "iat": datetime_utils.tz_aware_utc_now(),
                    # Missing iss.
                },
                key=rsa_key.export_key(),
                algorithm="RS256",
            )

        def it_throws_error(
            request_with_cookie: fastapi.Request,
            wallet_address: str,
            chain_id: str,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.InvalidIdTokenException):
                auth_utils.verify_wallet_ownership(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                    wallet_address=wallet_address,
                    chain_id=chain_id,
                )

    def if_the_token_has_expired() -> None:
        @pytest.fixture
        def token_expiration_time() -> datetime.datetime:
            return datetime_utils.tz_aware_utc_now() - datetime.timedelta(seconds=3)

        def it_throws_error(
            request_with_cookie: fastapi.Request,
            wallet_address: str,
            chain_id: str,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.InvalidIdTokenException):
                auth_utils.verify_wallet_ownership(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                    wallet_address=wallet_address,
                    chain_id=chain_id,
                )

    def if_the_token_issuer_is_not_huma() -> None:
        @pytest.fixture
        def token_issuer() -> str:
            return "not-huma.finance"

        def it_throws_error(
            request_with_cookie: fastapi.Request,
            wallet_address: str,
            chain_id: str,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.InvalidIdTokenException):
                auth_utils.verify_wallet_ownership(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                    wallet_address=wallet_address,
                    chain_id=chain_id,
                )

    def if_the_subject_is_invalid() -> None:
        @pytest.fixture
        def claim_sub() -> str:
            return "abcde"

        def it_throws_error(
            request_with_cookie: fastapi.Request,
            wallet_address: str,
            chain_id: str,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.InvalidIdTokenException):
                auth_utils.verify_wallet_ownership(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                    wallet_address=wallet_address,
                    chain_id=chain_id,
                )

    def if_the_wallet_address_mismatches() -> None:
        def it_throws_error(
            request_with_cookie: fastapi.Request, chain_id: str, rsa_key: RSA.RsaKey
        ) -> None:
            with pytest.raises(auth_utils.WalletMismatchException):
                auth_utils.verify_wallet_ownership(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                    wallet_address=address_helpers.fake_hex_address(),
                    chain_id=chain_id,
                )

    def if_the_chain_id_mismatches() -> None:
        def it_throws_error(
            request_with_cookie: fastapi.Request,
            wallet_address: str,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.WalletMismatchException):
                auth_utils.verify_wallet_ownership(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                    wallet_address=wallet_address,
                    chain_id="2",
                )

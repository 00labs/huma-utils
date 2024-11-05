import datetime
import uuid

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
    def token_expiration_time() -> datetime.datetime:
        return datetime_utils.tz_aware_utc_now() + datetime.timedelta(days=3)

    @pytest.fixture
    def token_issuer() -> str:
        return constants.HUMA_FINANCE_DOMAIN_NAME

    @pytest.fixture
    def id_token(
        wallet_address: str,
        chain_id: str,
        token_expiration_time: datetime.datetime,
        token_issuer: str,
        rsa_key: RSA.RsaKey,
    ) -> str:
        return auth_utils.create_auth_token(
            wallet_address=wallet_address,
            chain_id=chain_id,
            expires_at=token_expiration_time,
            jwt_private_key=rsa_key.export_key().decode(),
            issuer=token_issuer,
        )

    @pytest.fixture
    def id_token_cookie(id_token: str, wallet_address: str, chain_id: str) -> str:
        return f"id_token:{wallet_address}:{chain_id}={id_token}"

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
            chain_id: str,
            id_token: str,
            token_expiration_time: datetime.datetime,
            token_issuer: str,
            rsa_key: RSA.RsaKey,
        ) -> str:
            header, _, sig = id_token.split(".")
            new_token = auth_utils.create_auth_token(
                wallet_address=wallet_address,
                chain_id="2",
                expires_at=token_expiration_time,
                jwt_private_key=rsa_key.export_key().decode(),
                issuer=token_issuer,
            )
            _, new_token_payload, _ = new_token.split(".")
            # Replaces the claim with an invalid one to simulate the jwt being tampered with.
            return f"id_token:{wallet_address}:{chain_id}={'.'.join([header, new_token_payload, sig])}"

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
            wallet_address: str,
            chain_id: str,
            token_expiration_time: datetime.datetime,
            rsa_key: RSA.RsaKey,
        ) -> str:
            return jwt.encode(
                payload={
                    "sub": f"{wallet_address}:{chain_id}",
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
        def wallet_address() -> str:
            return "abcde:123"

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
        def if_the_wallet_address_mismatches_with_the_one_in_the_token() -> None:
            @pytest.fixture
            def wallet_address_2() -> str:
                return address_helpers.fake_hex_address()

            @pytest.fixture
            def id_token_cookie(
                id_token: str, wallet_address_2: str, chain_id: str
            ) -> str:
                return f"id_token:{wallet_address_2}:{chain_id}={id_token}"

            def it_throws_error(
                request_with_cookie: fastapi.Request,
                wallet_address_2: str,
                chain_id: str,
                rsa_key: RSA.RsaKey,
            ) -> None:
                with pytest.raises(auth_utils.WalletMismatchException):
                    auth_utils.verify_wallet_ownership(
                        request=request_with_cookie,
                        jwt_public_key=rsa_key.public_key().export_key().decode(),
                        wallet_address=wallet_address_2,
                        chain_id=chain_id,
                    )

        def if_the_wallet_address_mismatches_with_the_one_in_the_cookie_key() -> None:
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
                        wallet_address=address_helpers.fake_hex_address(),
                        chain_id=chain_id,
                    )

    def if_the_chain_id_mismatches() -> None:
        def if_the_chain_id_mismatches_with_the_one_in_the_token() -> None:
            @pytest.fixture
            def chain_id_2() -> str:
                return "2"

            @pytest.fixture
            def id_token_cookie(
                id_token: str, wallet_address: str, chain_id_2: str
            ) -> str:
                return f"id_token:{wallet_address}:{chain_id_2}={id_token}"

            def it_throws_error(
                request_with_cookie: fastapi.Request,
                wallet_address: str,
                rsa_key: RSA.RsaKey,
                chain_id_2: str,
            ) -> None:
                with pytest.raises(auth_utils.WalletMismatchException):
                    auth_utils.verify_wallet_ownership(
                        request=request_with_cookie,
                        jwt_public_key=rsa_key.public_key().export_key().decode(),
                        wallet_address=wallet_address,
                        chain_id=chain_id_2,
                    )

        def if_the_chain_id_mismatches_with_the_one_in_the_cookie_key() -> None:
            def it_throws_error(
                request_with_cookie: fastapi.Request,
                wallet_address: str,
                rsa_key: RSA.RsaKey,
            ) -> None:
                with pytest.raises(auth_utils.IdTokenNotFoundException):
                    auth_utils.verify_wallet_ownership(
                        request=request_with_cookie,
                        jwt_public_key=rsa_key.public_key().export_key().decode(),
                        wallet_address=wallet_address,
                        chain_id="2",
                    )


def describe_verify_account_token() -> None:
    @pytest.fixture(scope="session")
    def rsa_key() -> RSA.RsaKey:
        return RSA.generate(2048)

    @pytest.fixture
    def account_id() -> uuid.UUID:
        return uuid.uuid4()

    @pytest.fixture
    def token_expiration_time() -> datetime.datetime:
        return datetime_utils.tz_aware_utc_now() + datetime.timedelta(days=3)

    @pytest.fixture
    def token_issuer() -> str:
        return constants.HUMA_FINANCE_DOMAIN_NAME

    @pytest.fixture
    def account_token(
        account_id: uuid.UUID,
        token_expiration_time: datetime.datetime,
        token_issuer: str,
        rsa_key: RSA.RsaKey,
    ) -> str:
        return auth_utils.create_account_token(
            account_id=account_id,
            expires_at=token_expiration_time,
            jwt_private_key=rsa_key.export_key().decode(),
            issuer=token_issuer,
        )

    @pytest.fixture
    def account_token_cookie(account_token: str) -> str:
        return f"account_token={account_token}"

    @pytest.fixture
    def request_with_cookie(account_token_cookie: str) -> fastapi.Request:
        return fastapi.Request(
            scope={
                "type": "http",
                "headers": [("cookie".encode(), account_token_cookie.encode())],
            }
        )

    def it_performs_the_verification(
        account_id: uuid.UUID,
        request_with_cookie: fastapi.Request,
        rsa_key: RSA.RsaKey,
    ) -> None:
        actual_account_id = auth_utils.verify_account_token(
            request=request_with_cookie,
            jwt_public_key=rsa_key.public_key().export_key().decode(),
        )
        assert actual_account_id == account_id

    def if_the_cookie_is_missing() -> None:
        @pytest.fixture
        def account_token_cookie() -> str:
            return ""

        def it_throws_error(
            request_with_cookie: fastapi.Request,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.AccountTokenNotFoundException):
                auth_utils.verify_account_token(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                )

    def if_the_jwt_is_tampered_with() -> None:
        @pytest.fixture
        def account_token_cookie(
            account_id: uuid.UUID,
            account_token: str,
            token_expiration_time: datetime.datetime,
            token_issuer: str,
            rsa_key: RSA.RsaKey,
        ) -> str:
            header, _, sig = account_token.split(".")
            new_token = auth_utils.create_account_token(
                account_id=uuid.uuid4(),
                expires_at=token_expiration_time,
                jwt_private_key=rsa_key.export_key().decode(),
                issuer=token_issuer,
            )
            _, new_token_payload, _ = new_token.split(".")
            # Replaces the claim with an invalid one to simulate the jwt being tampered with.
            return f"account_token={'.'.join([header, new_token_payload, sig])}"

        def it_throws_error(
            request_with_cookie: fastapi.Request,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.InvalidAccountTokenException):
                auth_utils.verify_account_token(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                )

    def if_the_claim_is_malformed() -> None:
        @pytest.fixture
        def account_token(
            account_id: uuid.UUID,
            token_expiration_time: datetime.datetime,
            rsa_key: RSA.RsaKey,
        ) -> str:
            return jwt.encode(
                payload={
                    "sub": str(account_id),
                    "exp": token_expiration_time,
                    "iat": datetime_utils.tz_aware_utc_now(),
                    # Missing iss.
                },
                key=rsa_key.export_key(),
                algorithm="RS256",
            )

        def it_throws_error(
            request_with_cookie: fastapi.Request,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.InvalidAccountTokenException):
                auth_utils.verify_account_token(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                )

    def if_the_token_has_expired() -> None:
        @pytest.fixture
        def token_expiration_time() -> datetime.datetime:
            return datetime_utils.tz_aware_utc_now() - datetime.timedelta(seconds=3)

        def it_throws_error(
            request_with_cookie: fastapi.Request,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.InvalidAccountTokenException):
                auth_utils.verify_account_token(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                )

    def if_the_token_issuer_is_not_huma() -> None:
        @pytest.fixture
        def token_issuer() -> str:
            return "not-huma.finance"

        def it_throws_error(
            request_with_cookie: fastapi.Request,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.InvalidAccountTokenException):
                auth_utils.verify_account_token(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                )

    def if_the_subject_is_not_a_valid_uuid() -> None:
        @pytest.fixture
        def account_id() -> str:
            return "abcde"

        def it_throws_error(
            request_with_cookie: fastapi.Request,
            rsa_key: RSA.RsaKey,
        ) -> None:
            with pytest.raises(auth_utils.InvalidAccountTokenException):
                auth_utils.verify_account_token(
                    request=request_with_cookie,
                    jwt_public_key=rsa_key.public_key().export_key().decode(),
                )

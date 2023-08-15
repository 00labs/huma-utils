import datetime

import fastapi
import jwt
import pydantic

from huma_utils import constants


class JWTClaim(pydantic.BaseModel):
    sub: str
    exp: datetime.datetime
    iat: datetime.datetime
    iss: str


class WalletVerificationException(Exception):
    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}: {self.message}"


class IdTokenNotFoundException(WalletVerificationException):
    def __init__(self) -> None:
        super().__init__(message="ID token is required, but not found")


class InvalidIdTokenException(WalletVerificationException):
    def __init__(self) -> None:
        super().__init__(message="Invalid ID token")


class WalletMismatchException(WalletVerificationException):
    def __init__(self) -> None:
        super().__init__(
            message="The wallet address and/or chain ID does not match the ones in the ID token"
        )


def verify_wallet_ownership(
    request: fastapi.Request, jwt_public_key: str, wallet_address: str, chain_id: str
) -> None:
    id_token = request.cookies.get("id_token")
    if not id_token:
        raise IdTokenNotFoundException()

    try:
        jwt_claim = JWTClaim(
            **jwt.decode(
                jwt=id_token,
                key=jwt_public_key,
                algorithms=["RS256"],
                issuer=constants.HUMA_FINANCE_DOMAIN_NAME,
            )
        )
    except (pydantic.ValidationError, jwt.exceptions.PyJWTError) as e:
        raise InvalidIdTokenException() from e

    sub_parts = jwt_claim.sub.split(":")
    if len(sub_parts) != 2:
        raise InvalidIdTokenException()
    if wallet_address != sub_parts[0] or chain_id != sub_parts[1]:
        raise WalletMismatchException()

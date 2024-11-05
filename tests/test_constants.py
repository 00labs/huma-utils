import re

import pytest

from huma_utils import constants


def describe_SERVER_ALLOW_ORIGIN_REGEX() -> None:
    @pytest.mark.parametrize(
        "origin",
        [
            "https://pr-256.d382yqc38xh8lk.amplifyapp.com",
            "https://master.d382yqc38xh8lk.amplifyapp.com",
            "https://dev.app.huma.finance",
            "https://app.huma.finance",
            "https://local.bulla.network:1234",
            "https://dev.bulla.network",
            "https://banker.bulla.network",
            "http://localhost:3000",
        ],
    )
    def it_matches_the_allowed_origins(origin: str) -> None:
        assert re.match(constants.SERVER_ALLOW_ORIGIN_REGEX, origin) is not None

    @pytest.mark.parametrize(
        "origin",
        [
            "https://fake.app.huma.finance",
            "https://app.huma.fake",
            "https://local.bulla.network:4321",
            "http://localhost",
        ],
    )
    def it_mismatches_other_origins(origin: str) -> None:
        assert re.match(constants.SERVER_ALLOW_ORIGIN_REGEX, origin) is None

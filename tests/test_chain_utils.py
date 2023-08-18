import pytest

from huma_utils import chain_utils


def describe_Chain() -> None:
    def it_supports_polygon() -> None:
        assert chain_utils.Chain.POLYGON.chain_name() == "polygon"
        assert chain_utils.Chain.POLYGON.is_testnet() is False

    def it_supports_eth() -> None:
        assert chain_utils.Chain.ETHEREUM.chain_name() == "ethereum"
        assert chain_utils.Chain.ETHEREUM.is_testnet() is False

    def it_supports_goerli() -> None:
        assert chain_utils.Chain.GOERLI.chain_name() == "goerli"
        assert chain_utils.Chain.GOERLI.is_testnet() is True

    def it_does_not_support_unregistered_chains() -> None:
        with pytest.raises(ValueError):
            assert chain_utils.Chain("SOME_CHAIN") is None


def describe_CHAIN_ID_BY_NAME() -> None:
    def it_contains_the_id_for_all_chains() -> None:
        assert len(chain_utils.CHAIN_ID_BY_NAME) == len(chain_utils.Chain)

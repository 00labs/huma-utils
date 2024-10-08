import pydantic_settings
import pytest

from huma_utils import chain_utils, web3_utils


class Settings(pydantic_settings.BaseSettings):
    model_config = pydantic_settings.SettingsConfigDict(case_sensitive=False)

    chain: chain_utils.Chain
    web3_provider_url: str


settings = Settings()


def describe_get_w3() -> None:
    async def it_can_get_w3() -> None:
        w3 = await web3_utils.get_w3(settings.chain, settings.web3_provider_url)
        assert w3 is not None
        is_connected = await w3.is_connected()
        assert is_connected is True

        latest_block = await w3.eth.get_block("latest")
        assert latest_block is not None
        assert latest_block["number"] > 0
        assert latest_block["hash"] is not None

        block = await w3.eth.get_block(latest_block["hash"])
        assert block is not None
        assert block["number"] == latest_block["number"]

    async def it_raises_error_if_chain_is_not_matched_with_provider() -> None:
        with pytest.raises(ValueError):
            await web3_utils.get_w3(
                chain_utils.Chain.POLYGON, settings.web3_provider_url
            )

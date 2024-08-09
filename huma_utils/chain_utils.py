from __future__ import annotations

import enum


class UnsupportedChainException(Exception):
    def __init__(self, chain_id: str | int) -> None:
        super().__init__()
        self.message = f"Chain ID {chain_id} not supported"

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}: {self.message}"


class Chain(enum.StrEnum):
    ETHEREUM = "ETHEREUM"
    SEPOLIA = "SEPOLIA"
    POLYGON = "POLYGON"
    MUMBAI = "MUMBAI"
    CELO = "CELO"
    ALFAJORES = "ALFAJORES"

    def chain_name(self) -> str:
        return self.lower()

    def is_testnet(self) -> bool:
        return self.chain_name() in ("sepolia", "mumbai", "alfajores")


CHAIN_ID_BY_NAME = {
    Chain.ETHEREUM: 1,
    Chain.SEPOLIA: 11155111,
    Chain.POLYGON: 137,
    Chain.MUMBAI: 80001,
    Chain.CELO: 42220,
    Chain.ALFAJORES: 44787,
}

CHAIN_NAME_BY_ID = {v: k for k, v in CHAIN_ID_BY_NAME.items()}


def chain_from_id(chain_id: str | int) -> Chain:
    try:
        return CHAIN_NAME_BY_ID[int(chain_id)]
    except KeyError as e:
        raise UnsupportedChainException(chain_id) from e

from __future__ import annotations

import enum


class Chain(enum.StrEnum):
    ETHEREUM = enum.auto()
    GOERLI = enum.auto()
    SEPOLIA = enum.auto()
    POLYGON = enum.auto()
    MUMBAI = enum.auto()
    CELO = enum.auto()
    ALFAJORES = enum.auto()

    def chain_name(self) -> str:
        return self.lower()

    def is_testnet(self) -> bool:
        return self.chain_name() in ("goerli", "sepolia", "mumbai", "alfajores")


CHAIN_ID_BY_NAME = {
    Chain.ETHEREUM: 1,
    Chain.GOERLI: 5,
    Chain.SEPOLIA: 11155111,
    Chain.POLYGON: 137,
    Chain.MUMBAI: 80001,
    Chain.CELO: 42220,
    Chain.ALFAJORES: 44787,
}

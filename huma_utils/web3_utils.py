from __future__ import annotations

from typing import Any, Dict, Sequence, Type, Union

import web3
from web3 import eth, geth, module, net

from huma_utils import chain_utils

_MODULES: Dict[str, Union[Type[module.Module], Sequence[Any]]] = {
    "eth": eth.AsyncEth,  # type: ignore[attr-defined]
    "net": net.AsyncNet,
    "geth": (
        geth.Geth,
        {
            "txpool": geth.AsyncGethTxPool,
            "personal": geth.AsyncGethPersonal,
            "admin": geth.AsyncGethAdmin,
        },
    ),
}


async def get_w3(chain: chain_utils.Chain, web3_provider_url: str) -> web3.Web3:
    w3 = web3.Web3(
        provider=web3.Web3.AsyncHTTPProvider(web3_provider_url), modules=_MODULES  # type: ignore[arg-type]
    )
    if await w3.net.version != str(chain_utils.CHAIN_ID_BY_NAME[chain]):  # type: ignore
        raise ValueError(f"Web3 provider is not compatible with chain {chain.name}")
    return w3

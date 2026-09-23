"""Tests for seismic_web3.contract.shielded — ShieldedContract namespaces."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from eth_abi import encode
from web3 import Web3

from seismic_web3._types import (
    CompressedPublicKey,
    PrivateKey,
)
from seismic_web3.client import get_encryption
from seismic_web3.contract.shielded import AsyncShieldedContract, ShieldedContract

_NETWORK_PK = CompressedPublicKey(
    "0x028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0"
)
_CLIENT_SK = PrivateKey(
    "0xa30363336e1bb949185292a2a302de86e447d98f3a43d823c8c234d9e3e5ad77"
)
_ADDR = Web3.to_checksum_address("0xd3e8763675e4c425df46cc3b5c0f6cbdac396046")

COUNTER_ABI = [
    {
        "type": "function",
        "name": "setNumber",
        "inputs": [{"name": "newNumber", "type": "suint256"}],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "increment",
        "inputs": [],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "getNumber",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
]


def _make_encryption():
    return get_encryption(_NETWORK_PK, _CLIENT_SK)


class TestShieldedContract:
    def test_has_all_namespaces(self):
        """ShieldedContract should have all expected namespaces."""
        w3 = MagicMock()
        encryption = _make_encryption()
        pk = PrivateKey(b"\x01" * 32)
        addr = "0xd3e8763675e4c425df46cc3b5c0f6cbdac396046"

        contract = ShieldedContract(w3, encryption, pk, addr, COUNTER_ABI)

        assert hasattr(contract, "write")  # smart
        assert hasattr(contract, "read")  # smart
        assert hasattr(contract, "swrite")  # force shielded
        assert hasattr(contract, "sread")  # force shielded
        assert hasattr(contract, "twrite")  # force transparent
        assert hasattr(contract, "tread")  # force transparent
        assert hasattr(contract, "dwrite")  # debug

    def test_write_namespace_getattr_returns_callable(self):
        """write.setNumber should return a callable."""
        w3 = MagicMock()
        encryption = _make_encryption()
        pk = PrivateKey(b"\x01" * 32)
        addr = "0xd3e8763675e4c425df46cc3b5c0f6cbdac396046"

        contract = ShieldedContract(w3, encryption, pk, addr, COUNTER_ABI)
        fn = contract.write.setNumber
        assert callable(fn)

    def test_read_namespace_getattr_returns_callable(self):
        """read.setNumber should return a callable."""
        w3 = MagicMock()
        encryption = _make_encryption()
        pk = PrivateKey(b"\x01" * 32)
        addr = "0xd3e8763675e4c425df46cc3b5c0f6cbdac396046"

        contract = ShieldedContract(w3, encryption, pk, addr, COUNTER_ABI)
        fn = contract.read.setNumber
        assert callable(fn)

    def test_swrite_namespace_getattr_returns_callable(self):
        """swrite.setNumber should return a callable."""
        w3 = MagicMock()
        encryption = _make_encryption()
        pk = PrivateKey(b"\x01" * 32)
        addr = "0xd3e8763675e4c425df46cc3b5c0f6cbdac396046"

        contract = ShieldedContract(w3, encryption, pk, addr, COUNTER_ABI)
        fn = contract.swrite.setNumber
        assert callable(fn)

    def test_sread_namespace_getattr_returns_callable(self):
        """sread.setNumber should return a callable."""
        w3 = MagicMock()
        encryption = _make_encryption()
        pk = PrivateKey(b"\x01" * 32)
        addr = "0xd3e8763675e4c425df46cc3b5c0f6cbdac396046"

        contract = ShieldedContract(w3, encryption, pk, addr, COUNTER_ABI)
        fn = contract.sread.setNumber
        assert callable(fn)

    def test_dwrite_namespace_getattr_returns_callable(self):
        """dwrite.setNumber should return a callable."""
        w3 = MagicMock()
        encryption = _make_encryption()
        pk = PrivateKey(b"\x01" * 32)
        addr = "0xd3e8763675e4c425df46cc3b5c0f6cbdac396046"

        contract = ShieldedContract(w3, encryption, pk, addr, COUNTER_ABI)
        fn = contract.dwrite.setNumber
        assert callable(fn)

    def test_smart_transparent_read_forwards_value_and_gas(self):
        w3 = MagicMock()
        w3.eth.call.return_value = encode(["uint256"], [7])
        contract = ShieldedContract(
            w3,
            _make_encryption(),
            PrivateKey(b"\x01" * 32),
            _ADDR,
            COUNTER_ABI,
        )

        assert contract.read.getNumber(value=9, gas=0) == 7
        request = w3.eth.call.call_args.args[0]
        assert request["value"] == 9
        assert request["gas"] == 0


class TestAsyncShieldedContract:
    def test_has_all_namespaces(self):
        """AsyncShieldedContract should have all expected namespaces."""
        w3 = MagicMock()
        encryption = _make_encryption()
        pk = PrivateKey(b"\x01" * 32)
        addr = "0xd3e8763675e4c425df46cc3b5c0f6cbdac396046"

        contract = AsyncShieldedContract(w3, encryption, pk, addr, COUNTER_ABI)

        assert hasattr(contract, "write")  # smart
        assert hasattr(contract, "read")  # smart
        assert hasattr(contract, "swrite")  # force shielded
        assert hasattr(contract, "sread")  # force shielded
        assert hasattr(contract, "twrite")  # force transparent
        assert hasattr(contract, "tread")  # force transparent
        assert hasattr(contract, "dwrite")  # debug

    def test_write_namespace_getattr_returns_callable(self):
        """write.increment should return a callable (async version)."""
        w3 = MagicMock()
        encryption = _make_encryption()
        pk = PrivateKey(b"\x01" * 32)
        addr = "0xd3e8763675e4c425df46cc3b5c0f6cbdac396046"

        contract = AsyncShieldedContract(w3, encryption, pk, addr, COUNTER_ABI)
        fn = contract.write.increment
        assert callable(fn)

    @pytest.mark.asyncio
    async def test_smart_transparent_read_forwards_value_and_gas(self):
        w3 = MagicMock()
        w3.eth.call = AsyncMock(return_value=encode(["uint256"], [7]))
        contract = AsyncShieldedContract(
            w3,
            _make_encryption(),
            PrivateKey(b"\x01" * 32),
            _ADDR,
            COUNTER_ABI,
        )

        assert await contract.read.getNumber(value=9, gas=0) == 7
        request = w3.eth.call.call_args.args[0]
        assert request["value"] == 9
        assert request["gas"] == 0

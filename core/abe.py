"""
ABE / ABKEM interface for CamShield.

Protocol:
    κa,e = ABE.Enc(PKABE, EKe, πa,e)
    EKe  = ABE.Dec(PKABE, SKu, κa,e)

Properties:
- ABE encapsulates the epoch key EKe.
- ABE does not encrypt the video segment.
- ABE does not encrypt a per-record CEK.

Backends:
1. MockCPABE — policy-checking mock for environments without Charm-Crypto
2. CharmBSW07 — CP-ABE via Charm-Crypto (default in simulation and deployment)
"""

from __future__ import annotations

import base64
import json
import re
from abc import ABC, abstractmethod
from typing import Any


                                                                             
                
                                                                             

class CPABEBase(ABC):
    @abstractmethod
    def setup(self) -> tuple[Any, Any]:
        ...

    @abstractmethod
    def keygen(self, msk: Any, attributes: list[str]) -> Any:
        ...

    @abstractmethod
    def encrypt(self, mpk: Any, policy: str, message: bytes) -> bytes:
        ...

    @abstractmethod
    def decrypt(self, sk: Any, ciphertext: bytes) -> bytes | None:
        ...


                                                                             
                             
                                                                             

class MockCPABE(CPABEBase):
    """
    Mock CP-ABE backend.

    This is NOT cryptographically secure.

    It is used only to test CamShield protocol flow:
        policy -> capsule κa,e -> recover EKe if user attributes satisfy policy.

    Supported policy style:
        (ROLE_OWNER and PURPOSE_SURVEILLANCE and MODE_READ and SCOPE_cam01)

    A user can decrypt if all extracted attributes are contained in SKu.
    """

    def setup(self) -> tuple[Any, Any]:
        mpk = {"type": "mock_mpk"}
        msk = {"type": "mock_msk"}
        return mpk, msk

    def keygen(self, msk: Any, attributes: list[str]) -> dict[str, Any]:
        normalized = sorted({self._normalize_attr(a) for a in attributes})
        return {
            "type": "mock_sk",
            "attributes": normalized,
        }

    def encrypt(self, mpk: Any, policy: str, message: bytes) -> bytes:
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("MockCPABE encrypt() expects message bytes")

        capsule = {
            "type": "mock_abe_capsule",
            "policy": policy,
            "message_b64": base64.b64encode(bytes(message)).decode("ascii"),
        }

        return json.dumps(capsule, sort_keys=True).encode("utf-8")

    def decrypt(self, sk: Any, ciphertext: bytes) -> bytes | None:
        try:
            capsule = json.loads(ciphertext.decode("utf-8"))
        except Exception:
            return None

        if capsule.get("type") != "mock_abe_capsule":
            return None

        policy = capsule.get("policy", "")
        required_attrs = self.extract_policy_attributes(policy)

        user_attrs = set()
        if isinstance(sk, dict):
            user_attrs = {self._normalize_attr(a) for a in sk.get("attributes", [])}
        elif isinstance(sk, list):
            user_attrs = {self._normalize_attr(a) for a in sk}

        if not required_attrs <= user_attrs:
            return None

        try:
            return base64.b64decode(capsule["message_b64"])
        except Exception:
            return None

    @staticmethod
    def _normalize_attr(attr: str) -> str:
        return attr.strip().upper()

    @classmethod
    def extract_policy_attributes(cls, policy: str) -> set[str]:
        """
        Extract simple CP-ABE attributes from policy string.

        Example:
            (ROLE_OWNER and PURPOSE_SURVEILLANCE and MODE_READ and SCOPE_cam01)
        """
        tokens = re.findall(
            r"\b(?:ROLE|PURPOSE|MODE|SCOPE)_[A-Za-z0-9_:-]+\b",
            policy,
        )
        return {cls._normalize_attr(t) for t in tokens}


                                                                             
                 
                                                                             

def get_cpabe(use_charm: bool = False) -> CPABEBase:
    """
    Return the configured CP-ABE backend.

    use_charm=False selects MockCPABE.
    use_charm=True selects CharmBSW07 when Charm-Crypto is installed.
    """
    if not use_charm:
        return MockCPABE()

    try:
        from core.abe_charm import CharmBSW07, charm_available

        if charm_available():
            return CharmBSW07()
    except Exception:
        pass

    raise ImportError(
        "Charm-Crypto backend unavailable. Install charm-crypto-framework or use MockCPABE."
    )

"""
Charm-Crypto CP-ABE backend for CamShield.

This file provides a real CP-ABE backend using Charm-Crypto.

It implements the same interface as MockCPABE in core/abe.py:

    setup() -> (mpk, msk)
    keygen(msk, attributes) -> sk
    encrypt(mpk, policy, EKe) -> kappa
    decrypt(sk, kappa) -> EKe or None

CP-ABE mapping:
    kappa_{a,e} = ABE.Enc(PK_ABE, EK_e, policy_{a,e})
    EK_e        = ABE.Dec(PK_ABE, SK_u, kappa_{a,e})

Important:
- ABE protects the epoch key EK_e.
- AES-GCM still encrypts the actual video payload.

Charm note:
- Charm policy parser treats underscores specially.
- Therefore internal Charm attribute tokens must avoid underscores.
- External CamShield attributes such as ROLE_OWNER are normalized to ROLEOWNER.
"""

from __future__ import annotations

import re
from typing import Any


def charm_available() -> bool:
    try:
        from charm.toolbox.pairinggroup import PairingGroup
        from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
        from charm.adapters.abenc_adapt_hybrid import HybridABEnc
        from charm.core.engine.util import objectToBytes, bytesToObject

        group = PairingGroup("SS512")
        _ = group.random()
        return True
    except Exception:
        return False


class CharmBSW07:
    """
    Charm BSW07 CP-ABE backend with hybrid encryption.

    This is a real Charm-Crypto CP-ABE implementation.
    The hybrid adapter allows us to encrypt bytes such as a 32-byte epoch key.
    """

    def __init__(self, group_name: str = "SS512") -> None:
        from charm.toolbox.pairinggroup import PairingGroup
        from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
        from charm.adapters.abenc_adapt_hybrid import HybridABEnc

        self.group_name = group_name
        self.group = PairingGroup(group_name)
        self.cpabe = CPabe_BSW07(self.group)
        self.hybrid = HybridABEnc(self.cpabe, self.group)

        self.mpk = None
        self.msk = None

    def setup(self) -> tuple[Any, Any]:
        mpk, msk = self.hybrid.setup()
        self.mpk = mpk
        self.msk = msk
        return mpk, msk

    def keygen(self, msk: Any, attributes: list[str]) -> Any:
        if self.mpk is None:
            raise RuntimeError("setup() must be called before keygen().")

        attrs = [self._normalize_attr(a) for a in attributes]
        return self.hybrid.keygen(self.mpk, msk, attrs)

    def encrypt(self, mpk: Any, policy: str, message: bytes) -> bytes:
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("CharmBSW07.encrypt() expects message bytes.")

        from charm.core.engine.util import objectToBytes

        normalized_policy = self._normalize_policy(policy)

        ct = self.hybrid.encrypt(
            mpk,
            bytes(message),
            normalized_policy,
        )

        if ct is None:
            raise ValueError(f"Charm encryption failed. Normalized policy: {normalized_policy}")

                                                          
                                                                                      
        return objectToBytes(ct, self.group)

    def decrypt(self, sk: Any, ciphertext: bytes) -> bytes | None:
        if self.mpk is None:
            raise RuntimeError("setup() must be called before decrypt().")

        from charm.core.engine.util import bytesToObject

        try:
            ct = bytesToObject(ciphertext, self.group)

            recovered = self.hybrid.decrypt(
                self.mpk,
                sk,
                ct,
            )

            if recovered is None or recovered is False:
                return None

            if isinstance(recovered, bytes):
                return recovered

            if isinstance(recovered, bytearray):
                return bytes(recovered)

            if isinstance(recovered, str):
                return recovered.encode("utf-8")

            try:
                return bytes(recovered)
            except Exception:
                return None

        except Exception:
            return None

    @staticmethod
    def _normalize_attr(attr: str) -> str:
        """
        Convert CamShield attributes to Charm-safe attribute tokens.

        Examples:
            ROLE_OWNER           -> ROLEOWNER
            PURPOSE_SURVEILLANCE -> PURPOSESURVEILLANCE
            MODE_READ            -> MODEREAD
            SCOPE_CAM01          -> SCOPECAM01

        Epoch and revocation version live in Cap_u leases; SK_u stays stable.
        """
        cleaned = re.sub(r"[^A-Za-z0-9]", "", attr.strip().upper())
        if not cleaned:
            raise ValueError(f"Invalid empty ABE attribute after normalization: {attr!r}")
        return cleaned

    @classmethod
    def _normalize_policy(cls, policy: str) -> str:
        """
        Convert a CamShield policy to Charm-safe syntax.

        Input:
            (ROLE_OWNER and PURPOSE_SURVEILLANCE and MODE_READ)

        Output:
            ( ROLEOWNER and PURPOSESURVEILLANCE and MODEREAD )
        """
        text = policy.replace("(", " ( ").replace(")", " ) ")
        tokens = text.split()

        out = []
        for tok in tokens:
            low = tok.lower()
            if low in {"and", "or", "(", ")"}:
                out.append(low)
            else:
                out.append(cls._normalize_attr(tok))

        return " ".join(out)

from __future__ import annotations

import base64
from base64 import b64decode
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.epoch import derive_record_key

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                                                                                
GATEWAY_CORE_EXACT = Path(__file__).resolve().parent / "gateway_core_exact"
if GATEWAY_CORE_EXACT.exists():
    sys.path.insert(0, str(GATEWAY_CORE_EXACT))


def _lp(data: bytes) -> bytes:
    return len(data).to_bytes(8, "big") + data


def _u64(x: int) -> bytes:
    return int(x).to_bytes(8, "big")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()



def build_associated_data(
    *,
    rid: bytes,
    cid: str,
    sid: str,
    seq: int,
    timestamp: int,
    epoch: int,
    gamma: bytes,
) -> bytes:
    return b"".join([
        _lp(b"CamShield.aad.v1"),
        _lp(rid),
        _lp(cid.encode("utf-8")),
        _lp(sid.encode("utf-8")),
        _lp(_u64(seq)),
        _lp(_u64(timestamp)),
        _lp(_u64(epoch)),
        _lp(gamma),
    ])


def post_json(url: str, payload: dict, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            obj = json.loads(body)
        except Exception:
            obj = {"raw_text": body}
        raise RuntimeError(f"HTTP {e.code} from {url}: {json.dumps(obj, ensure_ascii=False)[:2000]}") from e


@dataclass
class LocalCharmClient:
    group_name: str
    mpk: Any
    sk_u: Any
    attrs: list[str]

    @classmethod
    def bootstrap(
        cls,
        gateway_url: str,
        client_id: str,
        camera_id: str,
        policy: str = "",
    ) -> "LocalCharmClient":
        from charm.toolbox.pairinggroup import PairingGroup
        from charm.core.engine.util import bytesToObject

        base = gateway_url.rstrip("/")

        cred = post_json(
            base + "/client/credential-setup",
            {"client_id": client_id, "camera_id": camera_id},
            timeout=30,
        )
        if not cred.get("ok"):
            raise RuntimeError(f"client credential setup failed: {cred}")

        bootstrap_payload: dict[str, Any] = {
            "client_id": client_id,
            "camera_id": camera_id,
        }
        if policy.strip():
            bootstrap_payload["policy"] = policy.strip()

        if cred.get("sk_u_b64") and cred.get("mpk_b64"):
            obj = cred
            obj["attrs"] = cred.get("attrs", [])
            obj["group"] = cred.get("group", "SS512")
        else:
            obj = post_json(
                base + "/client/charm-bootstrap",
                bootstrap_payload,
                timeout=30,
            )
            if not obj.get("ok"):
                raise RuntimeError(f"client Charm bootstrap failed: {obj}")

        group_name = obj.get("group", "SS512")
        group = PairingGroup(group_name)

        mpk = bytesToObject(base64.b64decode(obj["mpk_b64"]), group)
        sk_u = bytesToObject(base64.b64decode(obj["sk_u_b64"]), group)

        return cls(
            group_name=group_name,
            mpk=mpk,
            sk_u=sk_u,
            attrs=obj.get("attrs", []),
        )

    def _compat_fix_hybrid_ciphertext(self, ct):
        """
        Charm version compatibility fix.

        Some Charm builds serialize HybridABEnc c2 as a string.  Newer
        symcrypto.decrypt() expects c2 to be a dict with fields such as
        alg/iv/ct/mac.  If c2 is a JSON/Python-literal string, convert it
        back to dict before calling hybrid.decrypt().
        """
        import ast
        import json

        if not isinstance(ct, dict):
            return ct

        if "c2" not in ct:
            return ct

        c2 = ct.get("c2")

        if isinstance(c2, dict):
            return ct

        if isinstance(c2, (bytes, bytearray)):
            try:
                c2 = bytes(c2).decode("utf-8")
            except Exception:
                return ct

        if isinstance(c2, str):
            text = c2.strip()

                             
            try:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    fixed = dict(ct)
                    fixed["c2"] = obj
                    return fixed
            except Exception:
                pass

                                           
            try:
                obj = ast.literal_eval(text)
                if isinstance(obj, dict):
                    fixed = dict(ct)
                    fixed["c2"] = obj
                    return fixed
            except Exception:
                pass

        return ct

    def _decrypt_legacy_charm_c2(self, key_elem, c2) -> bytes | None:
        """
        Decrypt Charm ciphertexts produced by gateway-side HybridABEnc
        (charm-crypto-framework 0.63 layout):

            c1 = CPabe_BSW07.encrypt(pk, key, policy)
            c2 = AES-GCM_encrypt(sha256(key)[:32], EKe)

        Client-side recovery:

            key = CPabe_BSW07.decrypt(mpk, sk_u, c1)
            EKe = AES-GCM_decrypt(sha256(key)[:32], c2)
        """
        import json as _json
        from base64 import b64decode as _b64decode
        from charm.adapters import abenc_adapt_hybrid as hyb_mod
        from charm.core.crypto.AES_GCM import decrypt as _gcm_decrypt

        if isinstance(c2, (bytes, bytearray)):
            c2 = bytes(c2).decode("utf-8")

        if not isinstance(c2, str):
            return None

        payload = _json.loads(c2)

        if str(payload.get("ALG", "")).upper() != "AES-GCM":
            return None

        nonce = _b64decode(payload["Nonce"])
        ct_and_tag = _b64decode(payload["CipherText"])

        kraw = hyb_mod.sha2(key_elem)

        if isinstance(kraw, str):
            kraw = kraw.encode("utf-8")
        elif isinstance(kraw, bytearray):
            kraw = bytes(kraw)
        elif not isinstance(kraw, bytes):
            try:
                kraw = bytes(kraw)
            except Exception:
                return None

                                                                          
        key = kraw[:32]

        try:
            return _gcm_decrypt(key, ct_and_tag, nonce, aad=b"")
        except Exception as exc:
            print("[client_charm_local_decrypt] exact Charm AES_GCM decrypt failed:", repr(exc))
            return None

    def decrypt_kappa(self, kappa: bytes) -> bytes | None:
        from charm.toolbox.pairinggroup import PairingGroup
        from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
        from charm.adapters.abenc_adapt_hybrid import HybridABEnc
        from charm.core.engine.util import bytesToObject

        group = PairingGroup(self.group_name)
        cpabe = CPabe_BSW07(group)
        hybrid = HybridABEnc(cpabe, group)

        try:
            ct = bytesToObject(kappa, group)

                                                                               
            try:
                recovered = hybrid.decrypt(self.mpk, self.sk_u, ct)
                if recovered is not None and recovered is not False:
                    if isinstance(recovered, bytes):
                        return recovered
                    if isinstance(recovered, bytearray):
                        return bytes(recovered)
                    if isinstance(recovered, str):
                        return recovered.encode("utf-8")
                    try:
                        return bytes(recovered)
                    except Exception:
                        pass
            except Exception:
                pass

                                                                   
            if isinstance(ct, dict) and "c1" in ct and "c2" in ct:
                key_elem = cpabe.decrypt(self.mpk, self.sk_u, ct["c1"])
                if key_elem is False or key_elem is None:
                    return None
                return self._decrypt_legacy_charm_c2(key_elem, ct["c2"])

            return None

        except Exception as exc:
            print("[client_charm_local_decrypt] ABE decrypt exception:", repr(exc))
            return None

    def decrypt_record(self, record: dict) -> tuple[bool, bytes | None, dict]:
        rid = bytes.fromhex(record["rid"])
        epoch = int(record["epoch"])
        ssi = record["SSi"]

        kappa = bytes.fromhex(record["kappa"])
        EKe = self.decrypt_kappa(kappa)

        if EKe is None:
            return False, None, {
                "stage": "client_charm_abe_decrypt",
                "error": "Charm ABE decrypt failed",
                "attrs": self.attrs,
                "policy": record.get("policy"),
            }

        ki = derive_record_key(EKe, rid, epoch)

        aad = build_associated_data(
            rid=rid,
            cid=ssi["cid"],
            sid=ssi["sid"],
            seq=int(ssi["seq"]),
            timestamp=int(ssi["timestamp"]),
            epoch=epoch,
            gamma=bytes.fromhex(ssi["gamma"]),
        )

        try:
            plaintext = AESGCM(ki).decrypt(
                bytes.fromhex(record["nonce"]),
                bytes.fromhex(record["ciphertext"]) + bytes.fromhex(record["tag"]),
                aad,
            )
        except Exception as exc:
            return False, None, {
                "stage": "client_aes_gcm_decrypt",
                "error": repr(exc),
                "EKe_len": len(EKe),
            }

        hi_actual = _sha256(plaintext).hex()
        hi_expected = ssi["hi"]
        ok = hi_actual == hi_expected

        return ok, plaintext, {
            "decrypt_location": "client",
            "client_charm_abe_decrypt": True,
            "client_aes_gcm_decrypt": True,
            "hash_match": ok,
            "EKe_len": len(EKe),
            "plaintext_len": len(plaintext),
            "hi_expected": hi_expected,
            "hi_actual": hi_actual,
            "attrs": self.attrs,
            "result": "PASS" if ok else "CHECK",
        }


def records_from_json(path: str | Path) -> list[dict]:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))

    items = data.get("fetched_records", [])
    records = []

    for item in items:
        obj = item
        if isinstance(obj, dict) and isinstance(obj.get("response"), dict):
            obj = obj["response"]
        if isinstance(obj, dict) and isinstance(obj.get("record"), dict):
            obj = obj["record"]
        if isinstance(obj, dict) and "rid" in obj and "kappa" in obj:
            records.append(obj)

    return records


def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--gateway-url", default="http://127.0.0.1:8000")
    ap.add_argument("--client-id", default="owner")
    ap.add_argument("--camera-id", default="cam01")
    ap.add_argument("--epoch", type=int, default=8)
    ap.add_argument("--limit", type=int, default=3)
    args = ap.parse_args()

    records = records_from_json(args.input)
    if not records:
        raise SystemExit("[ERR] no encrypted records found in input")

    first_policy = records[0].get("policy", "")

    client = LocalCharmClient.bootstrap(
        gateway_url=args.gateway_url,
        client_id=args.client_id,
        camera_id=args.camera_id,
        policy=first_policy,
    )

    print("=" * 80)
    print("Mac Client-side Charm ABE + AES-GCM decrypt test")
    print("=" * 80)
    print("input  :", args.input)
    print("records:", len(records))
    print("attrs  :", client.attrs)
    print("policy :", first_policy)
    print("=" * 80)

    n = min(args.limit, len(records))
    passed = 0

    for i, rec in enumerate(records[:n], start=1):
        ok, plaintext, info = client.decrypt_record(rec)
        print(f"[{i}] rid={rec['rid'][:16]}... ok={ok}")
        print(json.dumps({
            "decrypt_location": info.get("decrypt_location"),
            "client_charm_abe_decrypt": info.get("client_charm_abe_decrypt"),
            "client_aes_gcm_decrypt": info.get("client_aes_gcm_decrypt"),
            "hash_match": info.get("hash_match"),
            "EKe_len": info.get("EKe_len"),
            "plaintext_len": info.get("plaintext_len"),
            "result": info.get("result"),
            "stage": info.get("stage"),
            "error": info.get("error"),
        }, indent=2, ensure_ascii=False))

        if ok:
            passed += 1

    if passed == n:
        print("RESULT: PASS - client-side Charm ABE + AES-GCM decrypt works.")
    else:
        raise SystemExit("RESULT: FAIL - some records failed client-side decrypt")


if __name__ == "__main__":
    main()

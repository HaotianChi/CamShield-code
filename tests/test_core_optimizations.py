"""Protocol-equivalence tests for the Gateway/Cloud ingest optimizations."""

from __future__ import annotations

import os
import copy
import sqlite3
import tempfile
import time
import threading
import unittest
import base64
import hashlib
from pathlib import Path
from unittest import mock

from core.abe import MockCPABE
from core import hmac_index
from core.cloud import Cloud
from core.cloud_server import create_app as create_cloud_app
from core.epoch import EpochManager
from core.gateway import Gateway
from core.gateway_persistence import (
    GatewayGroupedDurableStore,
    append_gateway_journal_event,
    compact_gateway_journal,
    externalize_pending_upload_payload,
    gateway_pending_upload_dir,
    gateway_persistence_metrics,
    load_pending_upload_payload,
    load_or_init_gateway_state,
    replay_gateway_transaction_store,
    remove_pending_upload_payload,
    save_gateway_state,
)
from core.gateway_server import (
    _finalize_epoch_checkpoint,
    _resolve_bool_env,
    create_app as create_gateway_app,
    rebuild_ordered_checkpoint_caches,
)
from core.models import CameraSignedSegment
from core.ordered_merkle import (
    NonMembershipProof,
    OrderedTokenLeaf,
    build_ordered_merkle_root,
    build_ordered_merkle_snapshot,
    canonical_json_bytes,
    leaf_hash_hex,
    make_real_token_id,
    parent_hash_hex,
    posting_digest_hex,
    posting_digest_hex_from_sorted_record_ids,
    verify_membership_proof,
    verify_non_membership_proof,
)
from core.camera import LocalTeeModule, TeeAttestRequest
from core.wire import camera_segment_to_json


class CountingABE(MockCPABE):
    def __init__(self) -> None:
        self.encrypt_calls = 0

    def encrypt(self, mpk, policy: str, message: bytes) -> bytes:
        self.encrypt_calls += 1
        return super().encrypt(mpk, policy, message)


class CoreOptimizationTests(unittest.TestCase):
    def test_rebuilt_gateway_merkle_caches_cannot_change_protocol_root(self) -> None:
        postings = {
            "01": {"aa", "bb"},
            "02": {"cc"},
        }
        state = {
            "token_to_record_ids_by_epoch": {"7": postings},
            # Deliberately stale values model a process recovery boundary.
            "_posting_digest_cache_by_epoch": {"7": {"01": "00" * 32}},
            "_ordered_token_ids_cache_by_epoch": {"7": ["1:02"]},
            "_sorted_posting_ids_cache_by_epoch": {"7": {"01": ["aa"]}},
        }
        rebuild_ordered_checkpoint_caches(state)
        expected = build_ordered_merkle_root(postings, checkpoint_version=9)
        actual = build_ordered_merkle_root(
            postings,
            checkpoint_version=9,
            posting_digest_by_token=state["_posting_digest_cache_by_epoch"]["7"],
            sorted_real_token_ids=state["_ordered_token_ids_cache_by_epoch"]["7"],
        )
        self.assertEqual(actual, expected)

    def test_sorted_posting_digest_cache_is_protocol_identical(self) -> None:
        posting = ["ff", "01", "c0", "01", "0a"]
        self.assertEqual(
            posting_digest_hex(posting),
            posting_digest_hex_from_sorted_record_ids(sorted(posting)),
        )

    def test_persistence_metrics_tolerate_upload_ack_file_removal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            state_path = Path(raw) / "gateway.json"
            state_path.write_text("{}", encoding="utf-8")
            pending_dir = gateway_pending_upload_dir(state_path)
            pending_dir.mkdir()
            disappearing = pending_dir / "disappearing.json"
            disappearing.write_text("{}", encoding="utf-8")
            original_stat = Path.stat
            victim_stat_calls = 0

            def racing_stat(path: Path, *args, **kwargs):
                nonlocal victim_stat_calls
                if path == disappearing:
                    victim_stat_calls += 1
                    if victim_stat_calls >= 2:
                        raise FileNotFoundError(disappearing)
                return original_stat(path, *args, **kwargs)

            with mock.patch.object(Path, "stat", racing_stat):
                metrics = gateway_persistence_metrics(state_path)

            self.assertEqual(metrics["pending_cloud_payload_count"], 0)
            self.assertEqual(metrics["pending_cloud_payload_bytes"], 0)

    def test_record_locator_search_tags_are_backward_compatible_by_default(self) -> None:
        self.assertEqual(
            hmac_index.keyword_set_for_record(
                "cam01", "segment-1", 7, ["event:motion"]
            ),
            ["camera:cam01", "segment:segment-1", "seq:7", "event:motion"],
        )

    def test_bounded_tag_profile_keeps_locators_out_of_search_only(self) -> None:
        self.assertEqual(
            hmac_index.keyword_set_for_record(
                "cam01",
                "segment-1",
                7,
                ["event:motion", "location:scale"],
                include_record_locators=False,
            ),
            ["camera:cam01", "event:motion", "location:scale"],
        )
        gateway = Gateway(abe=MockCPABE(), include_record_locator_tags=False)
        self.assertFalse(gateway.include_record_locator_tags)

        tee = LocalTeeModule("cam01")
        gateway.enroll_camera("cam01", tee.public_key)
        attested = tee.attest_segment(
            TeeAttestRequest(
                cid="cam01",
                sid="segment-1",
                seq=1,
                timestamp=123,
                raw_payload=b"h264-segment",
            )
        )
        segment = CameraSignedSegment(
            cid="cam01",
            sid="segment-1",
            seq=1,
            timestamp=123,
            raw_payload=b"h264-segment",
            hi=attested.hi,
            gamma_prev=attested.gamma_prev,
            gamma=attested.gamma,
            sigma_c=attested.sigma_c,
        )
        record = gateway.process_segment(
            segment,
            extra_keywords=["event:motion", "location:scale"],
            scope="cam01",
        )
        index_key = gateway.epoch_manager.index_key(record.epoch)
        expected_tokens = hmac_index.make_index_tokens(
            index_key,
            ["camera:cam01", "event:motion", "location:scale"],
            camera_id="cam01",
        )
        self.assertEqual(record.index_tokens, expected_tokens)

    def test_index_tag_profile_environment_is_strictly_parsed(self) -> None:
        with mock.patch.dict(
            os.environ, {"CAMSHIELD_INDEX_RECORD_LOCATOR_TAGS": "0"}
        ):
            self.assertFalse(
                _resolve_bool_env("CAMSHIELD_INDEX_RECORD_LOCATOR_TAGS", True)
            )
        with mock.patch.dict(
            os.environ, {"CAMSHIELD_INDEX_RECORD_LOCATOR_TAGS": "invalid"}
        ):
            with self.assertRaises(ValueError):
                _resolve_bool_env("CAMSHIELD_INDEX_RECORD_LOCATOR_TAGS", True)

    def test_fast_hash_serialization_matches_protocol_canonical_json(self) -> None:
        leaves = [
            OrderedTokenLeaf(
                token_id='1:01"\\unicode-\u4e2d',
                posting_digest_hex="aa" * 32,
                next_token_id="2:",
            ),
            OrderedTokenLeaf(
                token_id="1:02",
                posting_digest_hex="bb" * 32,
                previous_token_id="1:01",
                next_token_id="2:",
                checkpoint_version=17,
            ),
        ]
        for leaf in leaves:
            obj = {
                "type": (
                    "ordered-token-leaf-v2"
                    if leaf.is_v2
                    else "ordered-token-leaf-v1"
                ),
                **leaf.to_dict(),
            }
            expected = hashlib.sha256(canonical_json_bytes(obj)).hexdigest()
            self.assertEqual(leaf_hash_hex(leaf), expected)

        left = "11" * 32
        right = "22" * 32
        expected_parent = hashlib.sha256(canonical_json_bytes({
            "type": "ordered-merkle-parent-v1",
            "left": left,
            "right": right,
        })).hexdigest()
        self.assertEqual(parent_hash_hex(left, right), expected_parent)

    def test_root_only_builder_matches_full_snapshot(self) -> None:
        cases = [
            {},
            {"01": ["aa"]},
            {"01": {"aa", "bb"}, "ff": {"cc"}},
            {
                f"{index:064x}": {f"{rid:064x}" for rid in range(index + 1)}
                for index in range(12)
            },
        ]
        for postings in cases:
            with self.subTest(token_count=len(postings)):
                snapshot_postings = {
                    token: list(record_ids)
                    for token, record_ids in postings.items()
                }
                expected = build_ordered_merkle_snapshot(snapshot_postings).root_hex
                actual = build_ordered_merkle_root(postings)
                self.assertEqual(actual, expected)

    def test_cached_token_order_preserves_v1_and_v2_roots(self) -> None:
        postings = {
            "ff": {"04", "01"},
            "01": {"02"},
            "80": {"03", "05"},
        }
        sorted_token_ids = sorted(make_real_token_id(token) for token in postings)
        for version in (None, 1, 29):
            with self.subTest(checkpoint_version=version):
                uncached = build_ordered_merkle_root(
                    postings,
                    checkpoint_version=version,
                )
                cached = build_ordered_merkle_root(
                    postings,
                    checkpoint_version=version,
                    sorted_real_token_ids=sorted_token_ids,
                )
                snapshot = build_ordered_merkle_snapshot(
                    {token: list(rids) for token, rids in postings.items()},
                    checkpoint_version=version,
                )
                self.assertEqual(cached, uncached)
                self.assertEqual(cached, snapshot.root_hex)

    def test_protocol_aligned_leaf_binds_version_and_both_neighbors(self) -> None:
        postings = {"01": ["aa"], "03": ["bb"]}
        first = build_ordered_merkle_snapshot(postings, checkpoint_version=7)
        second = build_ordered_merkle_snapshot(postings, checkpoint_version=8)

        self.assertNotEqual(first.root_hex, second.root_hex)
        self.assertNotEqual(
            leaf_hash_hex(first.leaves["1:01"]),
            leaf_hash_hex(second.leaves["1:01"]),
        )
        leaf = first.leaves["1:01"]
        self.assertEqual(leaf.checkpoint_version, 7)
        self.assertEqual(leaf.previous_token_id, "0:")
        self.assertEqual(leaf.next_token_id, "1:03")

        proof = first.membership_proof("01")
        self.assertEqual(
            verify_membership_proof(
                first.root_hex,
                "01",
                ["aa"],
                proof,
                checkpoint_version=7,
            ),
            (True, "ok"),
        )
        ok, message = verify_membership_proof(
            first.root_hex,
            "01",
            ["aa"],
            proof,
            checkpoint_version=8,
        )
        self.assertFalse(ok, message)

    def test_v2_non_membership_binds_bidirectional_adjacency(self) -> None:
        snapshot = build_ordered_merkle_snapshot(
            {"01": ["aa"], "03": ["bb"]},
            checkpoint_version=4,
        )
        proof = snapshot.non_membership_proof("02")
        self.assertEqual(
            verify_non_membership_proof(
                snapshot.root_hex,
                "02",
                proof,
                checkpoint_version=4,
            ),
            (True, "ok"),
        )

        successor = proof.successor_leaf
        tampered = NonMembershipProof(
            query_token_id=proof.query_token_id,
            predecessor_leaf=proof.predecessor_leaf,
            predecessor_path=proof.predecessor_path,
            successor_leaf=OrderedTokenLeaf(
                token_id=successor.token_id,
                posting_digest_hex=successor.posting_digest_hex,
                next_token_id=successor.next_token_id,
                checkpoint_version=successor.checkpoint_version,
                previous_token_id="0:",
            ),
            successor_path=proof.successor_path,
        )
        ok, message = verify_non_membership_proof(
            snapshot.root_hex,
            "02",
            tampered,
            checkpoint_version=4,
        )
        self.assertFalse(ok)
        self.assertIn("point back", message)

    def test_legacy_v1_proof_remains_verifiable(self) -> None:
        snapshot = build_ordered_merkle_snapshot({"01": ["aa"]})
        proof = snapshot.membership_proof("01")
        self.assertEqual(
            verify_membership_proof(
                snapshot.root_hex,
                "01",
                ["aa"],
                proof,
            ),
            (True, "ok"),
        )

    def test_epoch_capsule_is_reused_for_same_epoch_and_policy(self) -> None:
        abe = CountingABE()
        gateway = Gateway(abe=abe, epoch_manager=EpochManager(epoch_duration_s=3600))
        epoch = gateway.epoch_manager.current_epoch()
        key = gateway.epoch_manager.epoch_key(epoch)

        first, first_hit = gateway._epoch_capsule(
            epoch=epoch,
            policy="(ROLE_OWNER and MODE_READ)",
            EKe=key,
        )
        second, second_hit = gateway._epoch_capsule(
            epoch=epoch,
            policy="(ROLE_OWNER and MODE_READ)",
            EKe=key,
        )

        self.assertFalse(first_hit)
        self.assertTrue(second_hit)
        self.assertEqual(first, second)
        self.assertEqual(abe.encrypt_calls, 1)

    def test_cloud_deferred_mode_verifies_root_before_returning_proofs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "cloud.sqlite3"
            postings = {"01": ["aa"]}
            checkpoint = {
                "type": "camshield-ordered-checkpoint-v1",
                "epoch": 1,
                "version": 1,
                "timestamp": 1,
                "root_hex": build_ordered_merkle_root(postings),
                "chain_hex": "00" * 32,
                "signature_b64": "",
                "gateway_public_key_b64": "",
            }
            record = {
                "epoch": 1,
                "SSi": {"cid": "cam01", "seq": 1, "timestamp": 1},
                "index_tokens": ["01"],
            }
            with mock.patch.dict(
                os.environ,
                {
                    "CAMSHIELD_CLOUD_DB": str(database),
                    "CAMSHIELD_API_TOKEN": "",
                    "CAMSHIELD_CLOUD_ROOT_VERIFY_MODE": "deferred",
                },
                clear=False,
            ):
                app = create_cloud_app()
                response = app.test_client().post(
                    "/store-batch",
                    json={
                        "epoch": 1,
                        "records": [{"rid": "aa", "record": record}],
                        "posting_updates": [{"token": "01", "rid": "aa"}],
                        "signed_checkpoint": checkpoint,
                    },
                )

                second_postings = {"01": ["aa", "bb"], "02": ["bb"]}
                second_checkpoint = {
                    **checkpoint,
                    "version": 2,
                    "root_hex": build_ordered_merkle_root(second_postings),
                }
                second_response = app.test_client().post(
                    "/store-batch",
                    json={
                        "epoch": 1,
                        "records": [{"rid": "bb", "record": record}],
                        "posting_updates": [
                            {"token": "01", "rid": "bb"},
                            {"token": "02", "rid": "bb"},
                        ],
                        "signed_checkpoint": second_checkpoint,
                    },
                )
                duplicate_response = app.test_client().post(
                    "/store-batch",
                    json={
                        "epoch": 1,
                        "records": [{"rid": "bb", "record": record}],
                        "posting_updates": [
                            {"token": "01", "rid": "bb"},
                            {"token": "02", "rid": "bb"},
                        ],
                        "signed_checkpoint": second_checkpoint,
                    },
                )
                searched = app.test_client().post(
                    "/search",
                    json={
                        "epoch": 1,
                        "operator": "AND",
                        "query_token_ids": ["01"],
                    },
                )

            data = response.get_json()
            self.assertEqual(response.status_code, 200, data)
            self.assertTrue(data["ok"])
            self.assertEqual(
                data["checkpoint_root_verification"], "deferred-to-query"
            )
            self.assertNotIn(
                "checkpoint_root_verify_ms", data["server_timing_ms"]
            )
            second_data = second_response.get_json()
            self.assertEqual(second_response.status_code, 200, second_data)
            self.assertEqual(
                duplicate_response.status_code, 200, duplicate_response.get_json()
            )
            self.assertEqual(
                second_data["checkpoint_root"], second_checkpoint["root_hex"]
            )
            self.assertIn(
                "posting_state_sync_ms", second_data["server_timing_ms"]
            )
            self.assertEqual(
                app.config["CAMSHIELD_CLOUD_STATE"].token_to_record_ids,
                second_postings,
            )
            self.assertEqual(
                app.config["CAMSHIELD_CLOUD_STATE"].posting_membership_by_token,
                {token: set(rids) for token, rids in second_postings.items()},
            )
            self.assertIsNone(app.config["CAMSHIELD_CLOUD_STATE"].snapshot)
            verified = app.test_client().post(
                "/admin/checkpoint/verify", json={"epoch": 1}
            )
            self.assertEqual(verified.status_code, 200, verified.get_json())
            self.assertEqual(
                verified.get_json()["verification_stage"], "epoch-boundary"
            )
            self.assertEqual(searched.status_code, 200, searched.get_json())
            app.config["CAMSHIELD_CLOUD_STATE"].store.close()

    def test_cloud_deferred_mode_rejects_bad_root_at_query(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "cloud-bad-root.sqlite3"
            checkpoint = {
                "type": "camshield-ordered-checkpoint-v2",
                "leaf_format": "ordered-token-leaf-v2",
                "epoch": 1,
                "version": 1,
                "timestamp": 1,
                "root_hex": "ff" * 32,
                "chain_hex": "00" * 32,
                "signature_b64": "",
                "gateway_public_key_b64": "",
            }
            record = {
                "epoch": 1,
                "SSi": {"cid": "cam01", "seq": 1, "timestamp": 1},
                "index_tokens": ["01"],
            }
            with mock.patch.dict(
                os.environ,
                {
                    "CAMSHIELD_CLOUD_DB": str(database),
                    "CAMSHIELD_API_TOKEN": "",
                    "CAMSHIELD_CLOUD_ROOT_VERIFY_MODE": "deferred",
                },
                clear=False,
            ):
                app = create_cloud_app()
                stored = app.test_client().post(
                    "/store-batch",
                    json={
                        "epoch": 1,
                        "records": [{"rid": "aa", "record": record}],
                        "posting_updates": [{"token": "01", "rid": "aa"}],
                        "signed_checkpoint": checkpoint,
                    },
                )
                searched = app.test_client().post(
                    "/search",
                    json={
                        "epoch": 1,
                        "operator": "AND",
                        "query_token_ids": ["01"],
                    },
                )
                verified = app.test_client().post(
                    "/admin/checkpoint/verify", json={"epoch": 1}
                )

            self.assertEqual(stored.status_code, 200, stored.get_json())
            self.assertEqual(searched.status_code, 409, searched.get_json())
            self.assertEqual(
                searched.get_json()["verification_stage"], "query"
            )
            self.assertEqual(verified.status_code, 409, verified.get_json())
            self.assertEqual(
                verified.get_json()["verification_stage"], "epoch-boundary"
            )
            app.config["CAMSHIELD_CLOUD_STATE"].store.close()

    def test_cloud_parallel_delivery_never_rolls_back_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "cloud-parallel.sqlite3"
            record = {
                "epoch": 1,
                "SSi": {"cid": "cam01", "seq": 1, "timestamp": 1},
                "index_tokens": ["01"],
            }
            checkpoint_v1 = {
                "type": "camshield-ordered-checkpoint-v2",
                "leaf_format": "ordered-token-leaf-v2",
                "epoch": 1,
                "version": 1,
                "timestamp": 1,
                "root_hex": build_ordered_merkle_root(
                    {"01": ["aa"]},
                    checkpoint_version=1,
                ),
                "chain_hex": "00" * 32,
                "signature_b64": "",
                "gateway_public_key_b64": "",
            }
            checkpoint_v2 = {
                **checkpoint_v1,
                "version": 2,
                "root_hex": build_ordered_merkle_root(
                    {"01": ["aa", "bb"]},
                    checkpoint_version=2,
                ),
            }
            with mock.patch.dict(
                os.environ,
                {
                    "CAMSHIELD_CLOUD_DB": str(database),
                    "CAMSHIELD_API_TOKEN": "",
                    "CAMSHIELD_CLOUD_ROOT_VERIFY_MODE": "deferred",
                },
                clear=False,
            ):
                app = create_cloud_app()
                client = app.test_client()
                newer = client.post(
                    "/store-batch",
                    json={
                        "epoch": 1,
                        "records": [{"rid": "bb", "record": record}],
                        "posting_updates": [{"token": "01", "rid": "bb"}],
                        "signed_checkpoint": checkpoint_v2,
                    },
                )
                older = client.post(
                    "/store-batch",
                    json={
                        "epoch": 1,
                        "records": [{"rid": "aa", "record": record}],
                        "posting_updates": [{"token": "01", "rid": "aa"}],
                        "signed_checkpoint": checkpoint_v1,
                    },
                )
                searched = client.post(
                    "/search",
                    json={
                        "epoch": 1,
                        "operator": "AND",
                        "query_token_ids": ["01"],
                    },
                )

            self.assertEqual(newer.status_code, 200, newer.get_json())
            self.assertTrue(newer.get_json()["checkpoint_advanced"])
            self.assertEqual(older.status_code, 200, older.get_json())
            self.assertFalse(older.get_json()["checkpoint_advanced"])
            self.assertEqual(older.get_json()["checkpoint_version"], 2)
            self.assertEqual(searched.status_code, 200, searched.get_json())
            self.assertEqual(
                app.config["CAMSHIELD_CLOUD_STATE"].store.checkpoint(1)["version"],
                2,
            )
            app.config["CAMSHIELD_CLOUD_STATE"].store.close()

    def test_cloud_transport_batch_commits_original_payloads_once(self) -> None:
        """Transport coalescing preserves each payload's checkpoint semantics."""
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "cloud-transport-batch.sqlite3"
            record_one = {
                "epoch": 1,
                "SSi": {"cid": "cam01", "seq": 1, "timestamp": 1},
                "index_tokens": ["01"],
            }
            record_two = {
                "epoch": 1,
                "SSi": {"cid": "cam02", "seq": 1, "timestamp": 2},
                "index_tokens": ["01"],
            }
            base_checkpoint = {
                "type": "camshield-ordered-checkpoint-v2",
                "leaf_format": "ordered-token-leaf-v2",
                "epoch": 1,
                "timestamp": 1,
                "chain_hex": "00" * 32,
                "signature_b64": "",
                "gateway_public_key_b64": "",
            }
            checkpoint_one = {
                **base_checkpoint,
                "version": 1,
                "root_hex": build_ordered_merkle_root(
                    {"01": ["aa"]}, checkpoint_version=1
                ),
            }
            checkpoint_two = {
                **base_checkpoint,
                "version": 2,
                "root_hex": build_ordered_merkle_root(
                    {"01": ["aa", "bb"]}, checkpoint_version=2
                ),
            }
            with mock.patch.dict(
                os.environ,
                {
                    "CAMSHIELD_CLOUD_DB": str(database),
                    "CAMSHIELD_API_TOKEN": "",
                    "CAMSHIELD_CLOUD_ROOT_VERIFY_MODE": "deferred",
                },
                clear=False,
            ):
                app = create_cloud_app()
                client = app.test_client()
                response = client.post(
                    "/store-batch-many",
                    json={
                        "batches": [
                            {
                                "epoch": 1,
                                "records": [{"rid": "aa", "record": record_one}],
                                "posting_updates": [{"token": "01", "rid": "aa"}],
                                "signed_checkpoint": checkpoint_one,
                            },
                            {
                                "epoch": 1,
                                "records": [{"rid": "bb", "record": record_two}],
                                "posting_updates": [{"token": "01", "rid": "bb"}],
                                "signed_checkpoint": checkpoint_two,
                            },
                        ]
                    },
                )
                searched = client.post(
                    "/search",
                    json={
                        "epoch": 1,
                        "operator": "AND",
                        "query_token_ids": ["01"],
                    },
                )

            data = response.get_json()
            self.assertEqual(response.status_code, 200, data)
            self.assertEqual(data["transport_batch_payloads"], 2)
            self.assertEqual(data["stored_records"], 2)
            self.assertEqual(data["checkpoint_version"], 2)
            self.assertEqual(searched.status_code, 200, searched.get_json())
            state = app.config["CAMSHIELD_CLOUD_STATE"]
            self.assertEqual(state.store_batches, 1)
            self.assertEqual(state.store_payloads, 2)
            state.store.close()

    def test_cloud_transport_batch_rolls_back_all_payloads_on_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "cloud-transport-rollback.sqlite3"
            checkpoint = {
                "type": "camshield-ordered-checkpoint-v2",
                "leaf_format": "ordered-token-leaf-v2",
                "epoch": 1,
                "version": 1,
                "timestamp": 1,
                "root_hex": build_ordered_merkle_root(
                    {"01": ["aa"]}, checkpoint_version=1
                ),
                "chain_hex": "00" * 32,
                "signature_b64": "",
                "gateway_public_key_b64": "",
            }
            record = {
                "epoch": 1,
                "SSi": {"cid": "cam01", "seq": 1, "timestamp": 1},
                "index_tokens": ["01"],
            }
            with mock.patch.dict(
                os.environ,
                {
                    "CAMSHIELD_CLOUD_DB": str(database),
                    "CAMSHIELD_API_TOKEN": "",
                    "CAMSHIELD_CLOUD_ROOT_VERIFY_MODE": "deferred",
                },
                clear=False,
            ):
                app = create_cloud_app()
                response = app.test_client().post(
                    "/store-batch-many",
                    json={
                        "batches": [
                            {
                                "epoch": 1,
                                "records": [{"rid": "aa", "record": record}],
                                "posting_updates": [{"token": "01", "rid": "aa"}],
                                "signed_checkpoint": checkpoint,
                            },
                            {"epoch": 1, "records": []},
                        ]
                    },
                )

            data = response.get_json()
            self.assertEqual(response.status_code, 400, data)
            self.assertEqual(data["failed_index"], 1)
            state = app.config["CAMSHIELD_CLOUD_STATE"]
            self.assertEqual(len(state.records), 0)
            self.assertIsNone(state.store.checkpoint(1))
            state.store.close()

    def test_cloud_synchronous_mode_remains_available_for_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "cloud-sync.sqlite3"
            postings = {"01": ["aa"]}
            checkpoint = {
                "type": "camshield-ordered-checkpoint-v1",
                "epoch": 1,
                "version": 1,
                "timestamp": 1,
                "root_hex": build_ordered_merkle_root(postings),
                "chain_hex": "00" * 32,
                "signature_b64": "",
                "gateway_public_key_b64": "",
            }
            record = {
                "epoch": 1,
                "SSi": {"cid": "cam01", "seq": 1, "timestamp": 1},
                "index_tokens": ["01"],
            }
            with mock.patch.dict(
                os.environ,
                {
                    "CAMSHIELD_CLOUD_DB": str(database),
                    "CAMSHIELD_API_TOKEN": "",
                    "CAMSHIELD_CLOUD_ROOT_VERIFY_MODE": "synchronous",
                },
                clear=False,
            ):
                app = create_cloud_app()
                stored = app.test_client().post(
                    "/store-batch",
                    json={
                        "epoch": 1,
                        "records": [{"rid": "aa", "record": record}],
                        "posting_updates": [{"token": "01", "rid": "aa"}],
                        "signed_checkpoint": checkpoint,
                    },
                )

            data = stored.get_json()
            self.assertEqual(stored.status_code, 200, data)
            self.assertEqual(data["checkpoint_root_verification"], "synchronous")
            self.assertIn("checkpoint_root_verify_ms", data["server_timing_ms"])
            app.config["CAMSHIELD_CLOUD_STATE"].store.close()

    def test_cloud_v2_store_and_search_use_checkpoint_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "cloud-v2.sqlite3"
            postings = {"01": ["aa"]}
            checkpoint = {
                "type": "camshield-ordered-checkpoint-v2",
                "leaf_format": "ordered-token-leaf-v2",
                "epoch": 1,
                "version": 3,
                "timestamp": 1,
                "root_hex": build_ordered_merkle_root(
                    postings,
                    checkpoint_version=3,
                ),
                "chain_hex": "00" * 32,
                "signature_b64": "",
                "gateway_public_key_b64": "",
            }
            record = {
                "epoch": 1,
                "SSi": {"cid": "cam01", "seq": 1, "timestamp": 1},
                "index_tokens": ["01"],
            }
            with mock.patch.dict(
                os.environ,
                {
                    "CAMSHIELD_CLOUD_DB": str(database),
                    "CAMSHIELD_API_TOKEN": "",
                    "CAMSHIELD_CLOUD_ROOT_VERIFY_MODE": "deferred",
                },
                clear=False,
            ):
                app = create_cloud_app()
                stored = app.test_client().post(
                    "/store-batch",
                    json={
                        "epoch": 1,
                        "records": [{"rid": "aa", "record": record}],
                        "posting_updates": [{"token": "01", "rid": "aa"}],
                        "signed_checkpoint": checkpoint,
                    },
                )
                searched = app.test_client().post(
                    "/search",
                    json={
                        "epoch": 1,
                        "operator": "AND",
                        "query_token_ids": ["01"],
                    },
                )

            self.assertEqual(stored.status_code, 200, stored.get_json())
            self.assertEqual(searched.status_code, 200, searched.get_json())
            proof = searched.get_json()["membership_proofs"]["01"]
            self.assertEqual(proof["leaf"]["checkpoint_version"], 3)
            self.assertIn("previous_token_id", proof["leaf"])
            app.config["CAMSHIELD_CLOUD_STATE"].store.close()

    def test_finalized_epoch_releases_only_gateway_posting_working_set(self) -> None:
        checkpoint = {"epoch": 7, "version": 9, "root_hex": "11" * 32}
        state = {
            "last_ordered_checkpoint": checkpoint,
            "final_epoch_checkpoints": {},
            "token_to_record_ids": {"aa": {"01"}},
            "token_to_record_ids_by_epoch": {
                "7": {"aa": {"01"}},
                "8": {"bb": {"02"}},
            },
            "_posting_digest_cache_by_epoch": {"7": {"aa": "22" * 32}},
            "_ordered_token_ids_cache_by_epoch": {"7": ["aa"]},
        }
        _finalize_epoch_checkpoint(state, Cloud(), 7)
        self.assertEqual(state["final_epoch_checkpoints"]["7"], checkpoint)
        self.assertNotIn("7", state["token_to_record_ids_by_epoch"])
        self.assertIn("8", state["token_to_record_ids_by_epoch"])
        self.assertEqual(state["token_to_record_ids"], {})
        self.assertNotIn("7", state["_posting_digest_cache_by_epoch"])
        self.assertNotIn("7", state["_ordered_token_ids_cache_by_epoch"])

    def test_grouped_wal_batches_and_replays_exact_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "gateway.json"
            first = Gateway(
                abe=MockCPABE(),
                epoch_manager=EpochManager(epoch_duration_s=3600),
            )
            tee = LocalTeeModule("cam01")
            first.enroll_camera("cam01", tee.public_key, expected_seq=1)
            base_state = {
                "record_count": 0,
                "last_checkpoint": None,
                "last_ordered_checkpoint": None,
                "token_to_record_ids": {},
                "token_to_record_ids_by_epoch": {},
                "ordered_checkpoint_version": 0,
                "ordered_checkpoint_version_by_epoch": {},
                "last_checkpoint_chain_by_epoch": {},
                "accepted_segments": {},
                "record_catalog": {},
                "pending_cloud_uploads": {},
            }
            save_gateway_state(first, base_state, state_path)
            store = GatewayGroupedDurableStore(
                state_path, batch_max=8, batch_wait_ms=20
            )
            tickets = []
            payloads = {}
            for index in range(8):
                rid = f"rid-{index}"
                payload = {"records": [{"rid": rid, "blob": "x" * 256}]}
                payloads[rid] = payload
                pending = {
                    "rid": rid,
                    "segment_key": f"cam01:{index + 1}:s{index + 1}",
                    "payload": payload,
                    "created_at": time.time(),
                }
                tickets.append(store.submit_ingest({
                    "type": "ingest-commit-v1",
                    "camera_id": "cam01",
                    "expected_seq": index + 2,
                    "last_gamma_hex": f"{index + 1:064x}",
                    "record_count": index + 1,
                    "segment_key": pending["segment_key"],
                    "response": {"ok": True},
                    "catalog": {
                        "rid": rid,
                        "cid": "cam01",
                        "sid": f"s{index + 1}",
                        "seq": index + 1,
                        "timestamp": index + 1,
                        "epoch": 1,
                        "tokens": ["01"],
                    },
                    "posting_updates": [{"token": "01", "rid": rid}],
                    "signed_checkpoint": {
                        "epoch": 1,
                        "version": index + 1,
                        "root_hex": f"{index + 1:064x}",
                        "chain_hex": f"{index + 2:064x}",
                    },
                    "pending_upload": pending,
                }))
            results = [ticket.wait(timeout=2.0) for ticket in tickets]
            self.assertTrue(any(
                result["gateway_durable_batch_records"] > 1
                for result in results
            ))
            connection = sqlite3.connect(str(store.db_path))
            try:
                codec, stored_payload, payload_bytes = connection.execute(
                    "SELECT payload_codec, payload_json, payload_bytes "
                    "FROM ingest_transactions WHERE rid = ?",
                    ("rid-0",),
                ).fetchone()
            finally:
                connection.close()
            self.assertEqual(codec, "zlib-json-v1")
            self.assertLess(len(stored_payload), payload_bytes)

            restored_gateway = Gateway(
                abe=MockCPABE(),
                epoch_manager=EpochManager(epoch_duration_s=3600),
            )
            restored_gateway.enroll_camera(
                "cam01", tee.public_key, expected_seq=1
            )
            restored = copy.deepcopy(base_state)
            replay = replay_gateway_transaction_store(
                restored_gateway, restored, state_path
            )
            self.assertEqual(replay["transaction_events"], 8)
            self.assertEqual(replay["pending_payloads"], 8)
            self.assertEqual(restored["record_count"], 8)
            self.assertEqual(
                restored_gateway.camera_registry.get_expected_seq("cam01"), 9
            )
            for rid, payload in payloads.items():
                self.assertEqual(
                    restored["pending_cloud_uploads"][rid]["payload"], payload
                )

            store.mark_uploaded(["rid-0"])
            store.flush()
            uploaded_gateway = Gateway(
                abe=MockCPABE(),
                epoch_manager=EpochManager(epoch_duration_s=3600),
            )
            uploaded_gateway.enroll_camera(
                "cam01", tee.public_key, expected_seq=1
            )
            uploaded_state = copy.deepcopy(base_state)
            replay_gateway_transaction_store(
                uploaded_gateway, uploaded_state, state_path
            )
            self.assertNotIn("rid-0", uploaded_state["pending_cloud_uploads"])
            self.assertEqual(len(uploaded_state["pending_cloud_uploads"]), 7)
            store.close()

    def test_grouped_wal_ingest_ack_waits_for_committed_transaction(self) -> None:
        class FakeResponse:
            status_code = 200
            text = ""

            @staticmethod
            def json():
                return {"ok": True, "server_timing_ms": {"total_ms": 1.0}}

        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "gateway.json"
            with (
                mock.patch.dict(os.environ, {
                    "CAMSHIELD_GATEWAY_STATE": str(state_path),
                    "CAMSHIELD_GATEWAY_PERSISTENCE_MODE": (
                        GatewayGroupedDurableStore.MODE
                    ),
                    "CAMSHIELD_GATEWAY_DURABLE_BATCH_MAX": "8",
                    "CAMSHIELD_GATEWAY_DURABLE_BATCH_WAIT_MS": "5",
                    "CAMSHIELD_GATEWAY_COMPACT_EVERY": "0",
                }),
                mock.patch(
                    "core.gateway_server._cloud_http_session.post",
                    return_value=FakeResponse(),
                ),
            ):
                app = create_gateway_app(
                    use_charm=False,
                    cloud_url="https://cloud.invalid",
                )
                client = app.test_client()
                tee = LocalTeeModule("cam01")
                enrolled = client.post(
                    "/enroll",
                    json={
                        "cid": "cam01",
                        "camera_public_key_b64": base64.b64encode(
                            tee.public_key_bytes
                        ).decode("ascii"),
                    },
                )
                self.assertEqual(enrolled.status_code, 200, enrolled.get_json())
                attested = tee.attest_segment(TeeAttestRequest(
                    cid="cam01",
                    sid="cam01-seg-000001",
                    seq=1,
                    timestamp=123,
                    raw_payload=b"h264-segment",
                ))
                segment = CameraSignedSegment(
                    cid="cam01",
                    sid="cam01-seg-000001",
                    seq=1,
                    timestamp=123,
                    raw_payload=b"h264-segment",
                    hi=attested.hi,
                    gamma_prev=attested.gamma_prev,
                    gamma=attested.gamma,
                    sigma_c=attested.sigma_c,
                )
                response = client.post(
                    "/ingest",
                    json={"segment": camera_segment_to_json(segment)},
                )
                self.assertEqual(response.status_code, 200, response.get_json())
                health = client.get("/health").get_json()
                self.assertEqual(
                    health["gateway_persistence_mode"],
                    GatewayGroupedDurableStore.MODE,
                )
                self.assertGreater(health["gateway_transaction_store_bytes"], 0)
                state = app.config["CAMSHIELD_GATEWAY_STATE"]
                deadline = time.time() + 2.0
                while state["pending_cloud_uploads"] and time.time() < deadline:
                    time.sleep(0.01)
                self.assertFalse(state["pending_cloud_uploads"])
                store = state["_gateway_durable_store"]
                store.flush()

                restored_gateway = Gateway(
                    abe=MockCPABE(),
                    epoch_manager=EpochManager(epoch_duration_s=3600),
                )
                restored = {"pending_cloud_uploads": {}}
                load_or_init_gateway_state(
                    restored_gateway, restored, state_path
                )
                replay_gateway_transaction_store(
                    restored_gateway, restored, state_path
                )
                self.assertEqual(restored["record_count"], 1)
                self.assertNotIn(
                    response.get_json()["rid"],
                    restored["pending_cloud_uploads"],
                )
                self.assertEqual(restored["cloud_uploads"], 1)
                store.close()

    def test_grouped_wal_migrates_legacy_payload_codec_column(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "gateway.json"
            db_path = state_path.with_suffix(state_path.suffix + ".transactions.sqlite3")
            connection = sqlite3.connect(str(db_path))
            try:
                connection.execute(
                    "CREATE TABLE ingest_transactions ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "rid TEXT NOT NULL UNIQUE, event_json BLOB NOT NULL, "
                    "payload_json BLOB, payload_bytes INTEGER NOT NULL, "
                    "uploaded INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL)"
                )
                connection.commit()
            finally:
                connection.close()
            store = GatewayGroupedDurableStore(state_path)
            try:
                connection = sqlite3.connect(str(db_path))
                try:
                    columns = {
                        row[1]
                        for row in connection.execute(
                            "PRAGMA table_info(ingest_transactions)"
                        )
                    }
                finally:
                    connection.close()
                self.assertIn("payload_codec", columns)
            finally:
                store.close()

    def test_grouped_wal_commit_failure_releases_no_success_ticket(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "gateway.json"
            store = GatewayGroupedDurableStore(
                state_path, batch_max=2, batch_wait_ms=50
            )

            def event(seq: int) -> dict:
                return {
                    "type": "ingest-commit-v1",
                    "pending_upload": {
                        "rid": "duplicate-rid",
                        "segment_key": f"cam01:{seq}:s{seq}",
                        "payload": {"records": [{"rid": "duplicate-rid"}]},
                        "created_at": time.time(),
                    },
                }

            first = store.submit_ingest(event(1))
            second = store.submit_ingest(event(2))
            with self.assertRaises(RuntimeError):
                first.wait(timeout=2.0)
            with self.assertRaises(RuntimeError):
                second.wait(timeout=2.0)

            connection = sqlite3.connect(str(store.db_path))
            try:
                committed = connection.execute(
                    "SELECT COUNT(*) FROM ingest_transactions"
                ).fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(committed, 0)
            self.assertIsNotNone(store.fatal_error)
            store.close()

    def test_gateway_journal_replays_commit_and_upload_ack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "gateway.json"
            first = Gateway(
                abe=MockCPABE(),
                epoch_manager=EpochManager(epoch_duration_s=3600),
            )
            tee = LocalTeeModule("cam01")
            first.enroll_camera("cam01", tee.public_key, expected_seq=1)
            base_state = {
                "record_count": 0,
                "last_checkpoint": None,
                "last_ordered_checkpoint": None,
                "token_to_record_ids": {},
                "token_to_record_ids_by_epoch": {},
                "ordered_checkpoint_version": 0,
                "ordered_checkpoint_version_by_epoch": {},
                "last_checkpoint_chain_by_epoch": {},
                "accepted_segments": {},
                "record_catalog": {},
                "pending_cloud_uploads": {},
            }
            save_gateway_state(first, base_state, state_path)
            checkpoint = {
                "epoch": 1,
                "version": 1,
                "root_hex": "11" * 32,
                "chain_hex": "22" * 32,
            }
            pending = {
                "rid": "aa",
                "segment_key": "cam01:1:s1",
                "payload": {"records": []},
            }
            append_gateway_journal_event(
                {
                    "type": "ingest-commit-v1",
                    "camera_id": "cam01",
                    "expected_seq": 2,
                    "last_gamma_hex": "33" * 32,
                    "record_count": 1,
                    "segment_key": "cam01:1:s1",
                    "response": {"ok": True, "cloud_upload": {"queued": True}},
                    "catalog": {
                        "rid": "aa",
                        "cid": "cam01",
                        "sid": "s1",
                        "seq": 1,
                        "timestamp": 1,
                        "epoch": 1,
                        "tokens": ["01"],
                    },
                    "posting_updates": [{"token": "01", "rid": "aa"}],
                    "signed_checkpoint": checkpoint,
                    "pending_upload": pending,
                },
                state_path,
            )
            self.assertNotIn("payload", pending)
            self.assertEqual(
                load_pending_upload_payload(pending, state_path),
                {"records": []},
            )
            self.assertEqual(
                len(list(gateway_pending_upload_dir(state_path).glob("*.json"))),
                1,
            )
            journal_path = state_path.with_suffix(
                state_path.suffix + ".journal.jsonl"
            )
            self.assertNotIn(b'"payload":{"records"', journal_path.read_bytes())
            with journal_path.open("ab") as handle:
                handle.write(b'{"type":"interrupted')

            second = Gateway(
                abe=MockCPABE(),
                epoch_manager=EpochManager(epoch_duration_s=3600),
            )
            restored = dict(base_state)
            load_or_init_gateway_state(second, restored, state_path)
            self.assertEqual(second.camera_registry.get_expected_seq("cam01"), 2)
            self.assertEqual(restored["record_count"], 1)
            self.assertEqual(restored["token_to_record_ids_by_epoch"]["1"]["01"], {"aa"})
            self.assertIn("aa", restored["pending_cloud_uploads"])
            self.assertTrue(journal_path.read_bytes().endswith(b"\n"))

            append_gateway_journal_event(
                {
                    "type": "cloud-upload-ack-v1",
                    "rid": "aa",
                    "segment_key": "cam01:1:s1",
                    "cloud_result": {"ok": True},
                    "cloud_uploads": 1,
                    "last_cloud_upload": {"rid": "aa"},
                },
                state_path,
            )
            third = Gateway(
                abe=MockCPABE(),
                epoch_manager=EpochManager(epoch_duration_s=3600),
            )
            restored_again = dict(base_state)
            load_or_init_gateway_state(third, restored_again, state_path)
            self.assertNotIn("aa", restored_again["pending_cloud_uploads"])
            self.assertEqual(restored_again["cloud_uploads"], 1)
            self.assertFalse(
                list(gateway_pending_upload_dir(state_path).glob("*.json"))
            )

    def test_compaction_bounds_journal_while_pending_payloads_remain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "gateway.json"
            gateway = Gateway(
                abe=MockCPABE(),
                epoch_manager=EpochManager(epoch_duration_s=3600),
            )
            state = {
                "record_count": 20,
                "pending_cloud_uploads": {},
            }
            for index in range(20):
                rid = f"rid-{index}"
                pending = {
                    "rid": rid,
                    "segment_key": f"cam01:{index}",
                    "payload": {"blob": "x" * 10_000},
                }
                state["pending_cloud_uploads"][rid] = pending
                append_gateway_journal_event(
                    {
                        "type": "ingest-commit-v1",
                        "camera_id": "cam01",
                        "expected_seq": index + 2,
                        "last_gamma_hex": "33" * 32,
                        "record_count": index + 1,
                        "segment_key": f"cam01:{index}",
                        "response": {"ok": True},
                        "catalog": {
                            "rid": rid,
                            "cid": "cam01",
                            "sid": str(index),
                            "seq": index + 1,
                            "timestamp": index,
                            "epoch": 1,
                            "tokens": [],
                        },
                        "posting_updates": [],
                        "signed_checkpoint": {
                            "epoch": 1,
                            "version": index + 1,
                            "root_hex": "11" * 32,
                            "chain_hex": "22" * 32,
                        },
                        "pending_upload": pending,
                    },
                    state_path,
                )

            before = gateway_persistence_metrics(state_path)
            self.assertEqual(before["pending_cloud_payload_count"], 20)
            self.assertGreater(before["pending_cloud_payload_bytes"], 190_000)
            self.assertLess(before["gateway_journal_bytes"], 100_000)

            compact_gateway_journal(gateway, state, state_path)
            after = gateway_persistence_metrics(state_path)
            self.assertEqual(after["gateway_journal_bytes"], 0)
            self.assertEqual(after["pending_cloud_payload_count"], 20)
            self.assertGreater(after["pending_cloud_payload_bytes"], 190_000)
            self.assertNotIn(
                b'"pending_cloud_uploads"',
                state_path.read_bytes(),
            )

            restored_gateway = Gateway(
                abe=MockCPABE(),
                epoch_manager=EpochManager(epoch_duration_s=3600),
            )
            restored_state = {"pending_cloud_uploads": {}}
            load_or_init_gateway_state(
                restored_gateway,
                restored_state,
                state_path,
            )
            self.assertEqual(len(restored_state["pending_cloud_uploads"]), 20)

    def test_durable_payload_removal_is_cloud_ack_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "gateway.json"
            gateway = Gateway(
                abe=MockCPABE(),
                epoch_manager=EpochManager(epoch_duration_s=3600),
            )
            state = {"pending_cloud_uploads": {}}
            save_gateway_state(gateway, state, state_path)
            pending = {
                "rid": "aa",
                "segment_key": "cam01:1:s1",
                "payload": {"records": [{"rid": "aa"}]},
            }
            append_gateway_journal_event(
                {
                    "type": "ingest-commit-v1",
                    "camera_id": "cam01",
                    "expected_seq": 2,
                    "last_gamma_hex": "33" * 32,
                    "record_count": 1,
                    "segment_key": "cam01:1:s1",
                    "response": {"ok": True},
                    "catalog": {
                        "rid": "aa",
                        "cid": "cam01",
                        "sid": "s1",
                        "seq": 1,
                        "timestamp": 1,
                        "epoch": 1,
                        "tokens": [],
                    },
                    "posting_updates": [],
                    "signed_checkpoint": {
                        "epoch": 1,
                        "version": 1,
                        "root_hex": "11" * 32,
                        "chain_hex": "22" * 32,
                    },
                    "pending_upload": pending,
                },
                state_path,
            )
            remove_pending_upload_payload(pending, state_path)

            restored_gateway = Gateway(
                abe=MockCPABE(),
                epoch_manager=EpochManager(epoch_duration_s=3600),
            )
            restored = {"pending_cloud_uploads": {}}
            load_or_init_gateway_state(restored_gateway, restored, state_path)
            self.assertNotIn("aa", restored["pending_cloud_uploads"])
            self.assertEqual(restored["cloud_uploads"], 1)

    def test_uncommitted_staged_payload_is_not_recovered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "gateway.json"
            pending = {
                "rid": "not-committed",
                "segment_key": "cam01:1:staged",
                "payload": {"records": [{"rid": "not-committed"}]},
            }
            externalize_pending_upload_payload(
                pending,
                state_path,
                staged=True,
            )
            self.assertFalse(
                list(gateway_pending_upload_dir(state_path).glob("*.json"))
            )
            self.assertTrue(
                list(gateway_pending_upload_dir(state_path).glob("*.staged"))
            )

            gateway = Gateway(
                abe=MockCPABE(),
                epoch_manager=EpochManager(epoch_duration_s=3600),
            )
            restored = {"pending_cloud_uploads": {}}
            save_gateway_state(gateway, restored, state_path)
            load_or_init_gateway_state(gateway, restored, state_path)
            self.assertNotIn("not-committed", restored["pending_cloud_uploads"])

    def test_remote_ingest_returns_after_durable_enqueue(self) -> None:
        class FakeResponse:
            status_code = 200
            text = ""

            @staticmethod
            def json():
                return {"ok": True, "server_timing_ms": {"total_ms": 1.0}}

        with (
            mock.patch("core.gateway_server.load_or_init_gateway_state"),
            mock.patch("core.gateway_server.save_gateway_state"),
            mock.patch("core.gateway_server.append_gateway_journal_event") as append,
            mock.patch(
                "core.gateway_server._cloud_http_session.post",
                return_value=FakeResponse(),
            ),
        ):
            app = create_gateway_app(
                use_charm=False,
                cloud_url="https://cloud.invalid",
            )
            client = app.test_client()
            tee = LocalTeeModule("cam01")
            client.post(
                "/enroll",
                json={
                    "cid": "cam01",
                    "camera_public_key_b64": base64.b64encode(
                        tee.public_key_bytes
                    ).decode("ascii"),
                },
            )
            attested = tee.attest_segment(
                TeeAttestRequest(
                    cid="cam01",
                    sid="cam01-seg-000001",
                    seq=1,
                    timestamp=123,
                    raw_payload=b"h264-segment",
                )
            )
            segment = CameraSignedSegment(
                cid="cam01",
                sid="cam01-seg-000001",
                seq=1,
                timestamp=123,
                raw_payload=b"h264-segment",
                hi=attested.hi,
                gamma_prev=attested.gamma_prev,
                gamma=attested.gamma,
                sigma_c=attested.sigma_c,
            )
            response = client.post(
                "/ingest", json={"segment": camera_segment_to_json(segment)}
            )
            data = response.get_json()
            self.assertEqual(response.status_code, 200, data)
            self.assertTrue(data["cloud_upload"]["queued"])
            # Transport observations are headers only: the durable JSON
            # receipt, its checkpoint fields, and its camera-chain semantics
            # remain unchanged.
            self.assertEqual(
                response.headers.get("X-CamShield-Transport-Timing-Version"),
                "v1",
            )
            for header in (
                "X-CamShield-Request-Body-Ms",
                "X-CamShield-JSON-Loads-Ms",
                "X-CamShield-Segment-Decode-Ms",
                "X-CamShield-Lock-Wait-Ms",
                "X-CamShield-Gateway-Protocol-Ms",
                "X-CamShield-Handler-Ms",
                "X-CamShield-Request-Bytes",
            ):
                self.assertGreaterEqual(float(response.headers[header]), 0.0)
            self.assertGreater(
                int(response.headers["X-CamShield-App-Started-Wall-Ns"]), 0
            )
            self.assertGreaterEqual(
                int(response.headers["X-CamShield-App-Responded-Wall-Ns"]),
                int(response.headers["X-CamShield-App-Started-Wall-Ns"]),
            )
            self.assertTrue(response.headers["X-CamShield-Worker-Pid"].isdigit())
            self.assertTrue(
                response.headers["X-CamShield-App-Thread-Id"].isdigit()
            )
            self.assertGreaterEqual(
                int(response.headers["X-CamShield-App-Active-At-Entry"]), 1
            )
            self.assertIn("server-timing", {
                key.lower() for key in response.headers.keys()
            })
            self.assertTrue(any(
                call.args[0].get("type") == "ingest-commit-v1"
                for call in append.call_args_list
            ))
            deadline = time.time() + 2
            state = app.config["CAMSHIELD_GATEWAY_STATE"]
            while state["pending_cloud_uploads"] and time.time() < deadline:
                time.sleep(0.01)
            self.assertFalse(state["pending_cloud_uploads"])

    def test_out_of_order_transport_wait_preserves_terminal_ack_order(self) -> None:
        """A later request may wait, but cannot advance the camera chain early."""
        with (
            mock.patch("core.gateway_server.load_or_init_gateway_state"),
            mock.patch("core.gateway_server.save_gateway_state"),
        ):
            app = create_gateway_app(use_charm=False, cloud_url=None)
            tee = LocalTeeModule("cam01")
            app.test_client().post(
                "/enroll",
                json={
                    "cid": "cam01",
                    "camera_public_key_b64": base64.b64encode(
                        tee.public_key_bytes
                    ).decode("ascii"),
                },
            )

            def segment_for(seq: int) -> CameraSignedSegment:
                attested = tee.attest_segment(
                    TeeAttestRequest(
                        cid="cam01",
                        sid=f"cam01-seg-{seq:06d}",
                        seq=seq,
                        timestamp=123 + seq,
                        raw_payload=f"h264-{seq}".encode("ascii"),
                    )
                )
                return CameraSignedSegment(
                    cid="cam01",
                    sid=f"cam01-seg-{seq:06d}",
                    seq=seq,
                    timestamp=123 + seq,
                    raw_payload=f"h264-{seq}".encode("ascii"),
                    hi=attested.hi,
                    gamma_prev=attested.gamma_prev,
                    gamma=attested.gamma,
                    sigma_c=attested.sigma_c,
                )

            first_segment = segment_for(1)
            second_segment = segment_for(2)
            later_result: dict[str, Any] = {}
            later_started = threading.Event()

            def post_later_segment() -> None:
                later_started.set()
                response = app.test_client().post(
                    "/ingest",
                    json={"segment": camera_segment_to_json(second_segment)},
                )
                later_result["response"] = response

            worker = threading.Thread(target=post_later_segment, daemon=True)
            worker.start()
            self.assertTrue(later_started.wait(timeout=1.0))
            time.sleep(0.03)
            self.assertTrue(worker.is_alive(), "seq=2 must wait for seq=1")

            first = app.test_client().post(
                "/ingest",
                json={"segment": camera_segment_to_json(first_segment)},
            )
            worker.join(timeout=2.0)
            self.assertFalse(worker.is_alive())
            second = later_result["response"]

            self.assertEqual(first.status_code, 200, first.get_json())
            self.assertEqual(second.status_code, 200, second.get_json())
            self.assertEqual(first.get_json()["record_count"], 1)
            self.assertEqual(second.get_json()["record_count"], 2)
            self.assertGreater(
                float(second.headers["X-CamShield-Sequence-Order-Wait-Ms"]),
                0.0,
            )
            registry = app.config["CAMSHIELD_GATEWAY"].camera_registry
            self.assertEqual(registry.get_expected_seq("cam01"), 3)


if __name__ == "__main__":
    unittest.main()

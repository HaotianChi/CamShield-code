# Attack-detection demos

Scripts under `demo/scenarios/` run a malicious Cloud that injects one inconsistency at a time. Use the client web console to observe verification outcomes.

## Procedure

1. Start the baseline stack and ingest records:

```bash
python roles/cloud.py
python roles/gateway.py --cloud-url http://127.0.0.1:8100
python run.py --mode deployment --role tee
python roles/camera.py --gateway http://127.0.0.1:8000 --max-segments 3
```

2. Stop the baseline Cloud service and start a scenario on port 8100:

```bash
python demo/scenarios/a01_hide_matching_records.py
# or: python demo/malicious_cloud.py --attack A7 --port 8100
```

3. Start the client web console:

```bash
python roles/client.py --gateway-url http://127.0.0.1:8000 --cloud-url http://127.0.0.1:8100
```

4. Run retrieval and verification with keywords matching ingested records. Inspect `retrieval_ok`, `binding_ok`, `decrypt_ok`, and `camera_ok` in the summary.

List scenarios:

```bash
python demo/list_attacks.py
```

## Scenarios (A1–A11)

| ID | Script | Typical signal |
|----|--------|----------------|
| A1 | `a01_hide_matching_records.py` | `retrieval_ok=false` |
| A2 | `a02_empty_search_result.py` | `retrieval_ok=false` |
| A3 | `a03_unrelated_ciphertext.py` | `decrypt_ok=false` / `binding_ok=false` |
| A4 | `a04_stale_checkpoint.py` | `retrieval_ok=false` |
| A5 | `a05_hide_newer_checkpoint.py` | `retrieval_ok=false` |
| A6 | `a06_partial_multi_tag_query.py` | `retrieval_ok=false` (AND, two keywords) |
| A7 | `a07_modify_ciphertext.py` | `decrypt_ok=false` |
| A8 | `a08_wrong_abe_capsule.py` | `decrypt_ok=false` |
| A9 | `a09_wrong_policy_digest.py` | `binding_ok=false` |
| A10 | `a10_record_metadata_mismatch.py` | `binding_ok=false` |
| A11 | `a11_wrong_segment_metadata.py` | `camera_ok=false` |

## Gateway ingest tamper

```bash
python demo/gateway_tampered_ingest.py --gateway-url http://127.0.0.1:8000
```

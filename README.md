# CamShield

**English** | [中文](README.zh-CN.md)

Source code for *CamShield: Bridging Privacy Protection and Evidence Readiness in Cloud-Assisted Surveillance*.

## Layout

```text
CamShield-code/
  run.py             Simulation and deployment runner
  roles/             Node entry points
  core/              Shared implementation
  demo/              Attack-detection demos
  requirements.txt   Dependencies
```

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

Requires Python 3.9+. Charm-Crypto may require additional build tools on some platforms.

## Simulation

```bash
python run.py
```

A successful run prints `SIMULATION RUN PASSED`.

```bash
python run.py --segments 3
python run.py --no-charm    # when Charm-Crypto is unavailable
```

## Deployment

Start each role in a separate terminal (adjust host addresses as needed):

```bash
python roles/cloud.py
python roles/gateway.py --cloud-url http://127.0.0.1:8100
python run.py --mode deployment --role tee
python roles/camera.py --gateway http://127.0.0.1:8000 --max-segments 10
```

Equivalent launcher:

```bash
python run.py --mode deployment --role gateway --cloud-url http://127.0.0.1:8100
```

### Client web console

```bash
python roles/client.py \
  --gateway-url http://127.0.0.1:8000 \
  --cloud-url http://127.0.0.1:8100
```

Open `http://127.0.0.1:5001` in a browser. Run outputs are stored under `web_runs/`.

## Demos

Attack-detection scenarios (malicious cloud, A1–A11) live under `demo/`. See [demo/README.md](demo/README.md) or:

```bash
python demo/list_attacks.py
```

## Dependencies

See `requirements.txt` (Flask, requests, cryptography, imageio-ffmpeg, charm-crypto-framework, pydantic).

## CI

GitHub Actions runs compile checks and basic tests (`python run.py --no-charm`) on push and pull requests to `main`. CI installs `requirements-ci.txt` (without Charm-Crypto).

## Citation

If you find this work useful, we would appreciate a citation:

```bibtex
@article{Chi2027CamShield,
  title   = {CamShield: Bridging privacy protection and evidence readiness in cloud-assisted surveillance},
  author  = {Chi, Haotian and Li, Yunwei and Zhao, Chunli and Geng, Haijun and Zhang, Rong and Wang, Yuwei},
  journal = {Computer Standards \& Interfaces},
  volume  = {100},
  pages   = {104211},
  year    = {2027},
  doi     = {10.1016/j.csi.2026.104211}
}
```

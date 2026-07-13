# CamShield

[English](README.md) | **中文**

*CamShield: Bridging Privacy Protection and Evidence Readiness in Cloud-Assisted Surveillance* 源代码仓库。

## 目录结构

```text
CamShield-code/
  run.py             仿真与部署启动器
  roles/             各节点入口
  core/              共享实现
  demo/              攻击检测演示
  requirements.txt   依赖列表
```

## 安装

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

需要 Python 3.9+。部分平台安装 Charm-Crypto 时需额外编译依赖。

## 仿真

```bash
python run.py
```

成功运行会输出 `SIMULATION RUN PASSED`。

```bash
python run.py --segments 3
python run.py --no-charm    # Charm-Crypto 不可用时
```

## 部署

各角色分别启动（请按实际地址修改主机名）：

```bash
python roles/cloud.py
python roles/gateway.py --cloud-url http://127.0.0.1:8100
python run.py --mode deployment --role tee
python roles/camera.py --gateway http://127.0.0.1:8000 --max-segments 10
```

亦可通过启动器：

```bash
python run.py --mode deployment --role gateway --cloud-url http://127.0.0.1:8100
```

### Client Web Console

```bash
python roles/client.py \
  --gateway-url http://127.0.0.1:8000 \
  --cloud-url http://127.0.0.1:8100
```

浏览器访问 `http://127.0.0.1:5001`。运行结果保存在 `web_runs/`。

## 演示

恶意 Cloud 攻击场景（A1–A11）位于 `demo/`。详见 [demo/README.md](demo/README.md) 或：

```bash
python demo/list_attacks.py
```

## 依赖

见 `requirements.txt`（Flask、requests、cryptography、imageio-ffmpeg、charm-crypto-framework、pydantic）。

## CI

推送到 `main` 或对其发起 PR 时，GitHub Actions 会执行编译检查与 smoke 测试（`python run.py --no-charm`）。CI 使用 `requirements-ci.txt`（不含 Charm-Crypto）。

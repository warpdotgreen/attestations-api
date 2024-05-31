# Attestations API

This API is used to manage validator attestations. Each week on Wednesday, a new 32-byte challenge is chosen by looking at recent Chia blocks. Validators sign the challenge to prove they still have access to their private keys. A guide can be found [here](https://docs.warp.green/validators/attestations).

## Install

```bash
python3 -m venv venv
. ./venv/bin/activate
pip install --extra-index-url https://pypi.chia.net/simple/ chia-dev-tools==1.2.6
pip install -r requirements.txt
cp .env.example .env
nano .env
```

## Run

```
uvicorn main:app --reload
```

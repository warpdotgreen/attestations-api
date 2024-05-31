from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import Tuple, List
from config import config
from db import *
import requests
import os

load_dotenv()
Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_weekly_challenge() -> Tuple[str, str]:
    chia_rpc_url = os.environ.get("CHIA_RPC_URL")
    blockchain_state = requests.get(f"{chia_rpc_url}/get_blockchain_state").json()

    peak_height = blockchain_state["blockchain_state"]["peak"]["height"]

    block_record_one = requests.post(f"{chia_rpc_url}/get_block_record_by_height", json={"height": peak_height - 64}).json()
    challenge_source_height = block_record_one["block_record"]["prev_transaction_block_height"]
    
    challenge_source = requests.post(f"{chia_rpc_url}/get_block_record_by_height", json={"height": challenge_source_height}).json()
    challenge = challenge_source["block_record"]["header_hash"][2:]
    proof = f"See https://xchscan.com/blocks/{challenge_source_height} or https://www.spacescan.io/block/{challenge_source_height} and check the header hash of block #{challenge_source_height}"
    
    return challenge, proof

def get_current_challenge(db: Session) -> Challenge:
    current_challenge = get_most_recent_challenge(db)
    if not current_challenge or int(time.time()) - current_challenge.created_at >= 7 * 24 * 60 * 60:
        new_challenge, time_proof = get_weekly_challenge()
        current_challenge = create_challenge(db, new_challenge, time_proof)
    return current_challenge


class ChallengeResponse(BaseModel):
    week: int
    challenge: str
    time_proof: str
    created_at: int

@app.get("/challenge")
def get_challenge(db: Session = Depends(get_db)) -> ChallengeResponse:
    chall = get_current_challenge(db)
    return ChallengeResponse(
        week=chall.week,
        challenge=chall.challenge,
        time_proof=chall.time_proof,
        created_at=chall.created_at
    )

class AttestationResponse(BaseModel):
    attestation_id: int
    validator_index: int
    signature: str
    week: int
    created_at: int

@app.post("/attestation")
def create_attestation(attestation: str, chain_type: str, db: Session = Depends(get_db)) -> AttestationResponse:
    validator_index = int(attestation.split("-")[0])
    try:
        actual_sig = bytes.fromhex(attestation.split("-")[-1])
    except:
        raise HTTPException(status_code=400, detail="Invalid signature")

    if validator_index < 0 or validator_index >= len(config["xch_cold_keys"]):
        raise HTTPException(status_code=400, detail="Invalid validator index")
    
    if chain_type not in ["evm", "chia"]:
        raise HTTPException(status_code=400, detail="Invalid chain type")

    current_challenge = get_current_challenge(db)
    if not current_challenge:
        raise HTTPException(status_code=400, detail="No current challenge available")
    
    db_attestation = get_attestation(db, validator_index, current_challenge.week)
    if db_attestation:
        raise HTTPException(status_code=400, detail="Attestation already exists for this challenge")
    
    public_key = bytes.fromhex(config["xch_cold_keys"][validator_index])
    if not verifySig(public_key, attestation.signature):
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    attestation: Attestation = create_attestation(db, attestation.validator_index, attestation.signature, current_challenge.id)
    return AttestationResponse(
        attestation_id=attestation.attestation_id,
        validator_index=attestation.validator_index,
        signature=attestation.signature,
        week=attestation.week,
        created_at=int(time.time())
    )


# @app.get("/overview")
# def read_attestations(db: Session = Depends(get_db)) -> List[AttestationResponse]:
#     return get_attestations_last_7_weeks(db)

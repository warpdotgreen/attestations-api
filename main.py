from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.blockchain_format.program import Program
from chia_rs import AugSchemeMPL, G1Element, G2Element
from fastapi import FastAPI, Depends, HTTPException
from eth_account.messages import encode_typed_data
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import Tuple, List
from config import config
from web3 import Web3
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

# https://github.com/warpdotgreen/cli/blob/master/commands/rekey.py#L480
def get_attestation_message(
    challenge: bytes32,
    validator_index: int,
) -> str:
    return f"Validator #{validator_index} attests having access to their cold private XCH key by signing this message with the following challenge: {challenge.hex()}".encode()


def verifyChiaSig(
    public_key: bytes,
    validator_index: int,
    signature: bytes,
    challenge: bytes32
) -> bool:
    message = get_attestation_message(challenge, validator_index)
    message_hash: bytes32 = Program.to(message).get_tree_hash()

    sig: G2Element = G2Element.from_bytes(signature)
    pubkey: G1Element = G1Element.from_bytes(public_key)

    return AugSchemeMPL.verify(pubkey, message_hash, sig)


def verifyEthSig(
    address: str,
    validator_index: int,
    signature: bytes,
    challenge: bytes32
) -> bool:
    domain = {
        "name": "warp.green Validator Attestations",
        "version": "1"
    }

    types = {
        "AttestationMessage": [
            {"name": "challenge", "type": "bytes32"},
            {"name": "validatorIndex", "type": "uint8"}
        ]
    }

    recoveredAddress = Web3.eth.account.recover_message(
        encode_typed_data(domain, types, {
            "challenge": '0x' + challenge.hex(),
            "validatorIndex": validator_index
        }),
        signature=signature
    )

    return recoveredAddress == address

class AttestationResponse(BaseModel):
    attestation_id: int
    validator_index: int
    chain_type: str
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
    
    # verify signature
    if (
        chain_type == "evm" and not verifyEthSig(config["eth_cold_addresses"][validator_index], validator_index, actual_sig, bytes.fromhex(current_challenge.challenge))
    ) or not verifyChiaSig(config["xch_cold_keys"][validator_index], validator_index, actual_sig, bytes.fromhex(current_challenge.challenge)):
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    attestation: Attestation = create_attestation(db, validator_index, actual_sig.hex(), chain_type, current_challenge.week)
    return AttestationResponse(
        attestation_id=attestation.attestation_id,
        validator_index=attestation.validator_index,
        chain_type=chain_type,
        signature=attestation.signature,
        week=attestation.week,
        created_at=int(time.time())
    )


class WeekInfo(BaseModel):
    week_name: str
    challenge_info: ChallengeResponse | None
    attestations: List[AttestationResponse]

class OverviewResponse(BaseModel):
    week_infos: List[WeekInfo]

@app.get("/overview")
def get_overview(db: Session = Depends(get_db)) -> OverviewResponse:
    current_challenge = get_current_challenge(db)

    week_infos = []
    challenges = get_challenges_last_7_weeks(db)
    attestations = get_attestations_last_7_weeks(db)
    for week_offest in range(7):
        week = current_challenge.week - week_offest
        if week < 1:
            week_name = "Not Monitored"
            week_infos.append(WeekInfo(
                week_name=week_name,
                challenge_info=None,
                attestations=[]
            ))
            continue

        week_name = f"Week {week}"
        week_challenge = next((c for c in challenges if c.week == week), None)
        week_attestations = [a for a in attestations if a.week == week]
        week_infos.append(WeekInfo(
            week_name=week_name,
            challenge_info=ChallengeResponse(
                week=week_challenge.week,
                challenge=week_challenge.challenge,
                time_proof=week_challenge.time_proof,
                created_at=week_challenge.created_at
            ),
            attestations=[AttestationResponse(
                attestation_id=a.attestation_id,
                validator_index=a.validator_index,
                chain_type=a.chain_type,
                signature=a.signature,
                week=a.week,
                created_at=a.created_at
            ) for a in week_attestations]
        ))

    return OverviewResponse(week_infos=week_infos)

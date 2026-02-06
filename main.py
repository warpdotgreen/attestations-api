from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.blockchain_format.program import Program
from chia_rs import AugSchemeMPL, G1Element, G2Element
from fastapi import FastAPI, Depends, HTTPException
from eth_account.messages import encode_typed_data
from fastapi.middleware.cors import CORSMiddleware
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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_period_challenge() -> Tuple[str, str]:
    chia_rpc_url = os.environ.get("CHIA_RPC_URL")
    blockchain_state = requests.post(f"{chia_rpc_url}/get_blockchain_state").json()

    peak_height = blockchain_state["blockchain_state"]["peak"]["height"]

    block_record_one = requests.post(f"{chia_rpc_url}/get_block_record_by_height", json={"height": peak_height - 64}).json()
    challenge_source_height = block_record_one["block_record"]["prev_transaction_block_height"]
    
    challenge_source = requests.post(f"{chia_rpc_url}/get_block_record_by_height", json={"height": challenge_source_height}).json()
    challenge = challenge_source["block_record"]["header_hash"][2:]
    proof = f"See https://xchscan.com/blocks/{challenge_source_height} or https://www.spacescan.io/block/{challenge_source_height} and check the header hash of block #{challenge_source_height}"
    
    return challenge, proof

def get_current_challenge(db: Session) -> Challenge:
    current_challenge = get_most_recent_challenge(db)
    if not current_challenge or (current_challenge.week <= 12 and int(time.time()) - current_challenge.created_at >= 7 * 24 * 60 * 60) or int(time.time()) - current_challenge.created_at >= 28 * 24 * 60 * 60:
        new_challenge, time_proof = get_period_challenge()
        increment = 1 if current_challenge.week <= 12 else 4
        current_challenge = create_challenge(db, current_challenge.week + increment,new_challenge, time_proof)
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

    web3 = Web3()
    recoveredAddress = web3.eth.account.recover_message(
        encode_typed_data(domain, types, {
            "challenge": '0x' + challenge.hex(),
            "validatorIndex": validator_index
        }),
        signature='0x' + signature.hex()
    )

    return recoveredAddress == address

class AttestationCreationRequest(BaseModel):
    chain_type: str
    attestation: str

class AttestationResponse(BaseModel):
    attestation_id: int
    validator_index: int
    chain_type: str
    signature: str
    week: int
    created_at: int

@app.post("/attestation")
def post_attestation(request: AttestationCreationRequest, db: Session = Depends(get_db)) -> AttestationResponse:
    attestation = request.attestation
    chain = request.chain_type

    validator_index = int(attestation.split("-")[0])
    try:
        actual_sig = bytes.fromhex(attestation.split("-")[-1])
    except:
        raise HTTPException(status_code=400, detail="Invalid signature")

    if validator_index < 0 or validator_index >= len(config["xch_cold_keys"]):
        raise HTTPException(status_code=400, detail="Invalid validator index")
    
    if chain not in ["evm", "chia"]:
        raise HTTPException(status_code=400, detail="Invalid chain type")

    current_challenge = get_current_challenge(db)
    if not current_challenge:
        raise HTTPException(status_code=400, detail="No current challenge available")
    
    db_attestation = get_attestation(db, validator_index, current_challenge.week, chain)
    if db_attestation:
        raise HTTPException(status_code=400, detail="Attestation already exists for this challenge")
    
    # verify signature
    if (
        chain == "evm" and not verifyEthSig(
            config["evm_cold_addresses"][validator_index],
            validator_index,
            actual_sig, 
            bytes.fromhex(current_challenge.challenge)
        )
    ) or (
        chain == "chia" and not verifyChiaSig(
            bytes.fromhex(config["xch_cold_keys"][validator_index]),
            validator_index,
            actual_sig,
            bytes.fromhex(current_challenge.challenge)
        )
    ):
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    attestation: Attestation = create_attestation(db, validator_index, actual_sig.hex(), chain, current_challenge.week)
    return AttestationResponse(
        attestation_id=attestation.attestation_id,
        validator_index=attestation.validator_index,
        chain_type=chain,
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
    xch_pubkeys: List[str]
    eth_addresses: List[str]

@app.get("/overview")
def get_overview(db: Session = Depends(get_db)) -> OverviewResponse:
    current_challenge = get_current_challenge(db)

    week_infos = []
    challenges = get_challenges_last_28_weeks(db)
    attestations = get_attestations_last_28_weeks(db)
    week_offset = 0
    for _ in range(7):
        week = current_challenge.week - week_offset
        week_offset += 1 if week <= 13 else 4

        if week < 1:
            week_name = "-"
            week_infos.append(WeekInfo(
                week_name=week_name,
                challenge_info=None,
                attestations=[]
            ))
            continue

        week_name = f"Weeks #{week}-{week + 3}"
        if week <= 12:
            week_name = f"Week #{week}"
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

    return OverviewResponse(
        week_infos=week_infos,
        xch_pubkeys=config["xch_cold_keys"],
        eth_addresses=config["evm_cold_addresses"]
    )


@app.get("/notifications")
def get_notifications(db: Session = Depends(get_db)) -> dict[int, str]:
    current_challenge = get_current_challenge(db)
    
    # If challenge is less than 14 days old, no notifications needed
    fourteen_days_seconds = 14 * 24 * 60 * 60
    challenge_age = int(time.time()) - current_challenge.created_at
    
    notifications = {}
    for validator_index in range(11):  # 0 to 10 inclusive
        validator_index = str(validator_index)
        if challenge_age < fourteen_days_seconds:
            notifications[validator_index] = ""
            continue
        
        # Check for attestations
        xch_attestation = get_attestation(db, validator_index, current_challenge.week, "chia")
        evm_attestation = get_attestation(db, validator_index, current_challenge.week, "evm")
        
        has_xch = xch_attestation is not None
        has_evm = evm_attestation is not None
        
        if has_xch and has_evm:
            notifications[validator_index] = ""
        elif not has_xch and not has_evm:
            notifications[validator_index] = "Missing XCH and EVM attestation(s)"
        elif not has_xch:
            notifications[validator_index] = "Missing XCH attestation(s)"
        else:
            notifications[validator_index] = "Missing EVM attestation(s)"
    
    return notifications

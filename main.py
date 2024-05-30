from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from db import *

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_weekly_challenge():
    # Replace this with your actual logic to generate the challenge
    return b'\x00' * 32, "no proof for PoC"

def get_current_challenge(db: Session) -> Challenge:
    current_challenge = get_most_recent_challenge(db)
    if not current_challenge or int(time.time()) - current_challenge.created_at >= 7 * 24 * 60 * 60:
        new_challenge, time_proof = get_weekly_challenge()
        current_challenge = create_challenge(db, new_challenge.hex(), time_proof)
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

class AttestationCreate(BaseModel):
    validator_index: int
    signature: str


class AttestationResponse(BaseModel):
    attestation_id: int
    validator_index: int
    signature: str
    week: int
    created_at: int

@app.post("/attestation")
def create_attestation(attestation: AttestationCreate, db: Session = Depends(get_db)) -> AttestationResponse:
    current_challenge = get_current_challenge(db)
    if not current_challenge:
        raise HTTPException(status_code=400, detail="No current challenge available")
    
    db_attestation = get_attestation(db, attestation.validator_index, current_challenge.week)
    if db_attestation:
        raise HTTPException(status_code=400, detail="Attestation already exists for this challenge")
    
    # You need to implement verifySig logic here
    # if not verifySig(public_key, attestation.signature):
    #     raise HTTPException(status_code=400, detail="Invalid signature")
    
    attestation: Attestation = create_attestation(db, attestation.validator_index, attestation.signature, current_challenge.id)
    return AttestationResponse(
        attestation_id=attestation.attestation_id,
        validator_index=attestation.validator_index,
        signature=attestation.signature,
        week=attestation.week,
        created_at=int(attestation.created_at.timestamp())
    )


# @app.get("/overview")
# def read_attestations(db: Session = Depends(get_db)) -> List[AttestationResponse]:
#     return get_attestations_last_7_weeks(db)

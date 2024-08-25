from sqlalchemy import Column, String, Integer, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import List
import time

SQLALCHEMY_DATABASE_URL = "sqlite:///./data.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Challenge(Base):
    __tablename__ = 'challenges'

    week = Column(Integer, primary_key=True, autoincrement=True)
    challenge = Column(String, unique=True)
    time_proof = Column(String)
    created_at = Column(Integer, index=True)

class Attestation(Base):
    __tablename__ = 'attestations'

    attestation_id = Column(Integer, primary_key=True, autoincrement=True)
    validator_index = Column(Integer, index=True)
    signature = Column(String)
    chain_type = Column(String, index=True) # evm or chia
    week = Column(Integer, index=True)
    created_at = Column(Integer, index=True)

def get_most_recent_challenge(db: Session):
    return db.query(Challenge).order_by(Challenge.created_at.desc()).first()

def create_challenge(db: Session, week: int, challenge: str, time_proof: str):
    db_challenge = Challenge(
        week=week,
        challenge=challenge,
        time_proof=time_proof,
        created_at=int(time.time())
    )
    db.add(db_challenge)
    db.commit()
    db.refresh(db_challenge)
    return db_challenge

def get_attestation(db: Session, validator_index: int, week: int, chain_type: str) -> Challenge | None:
    return db.query(Attestation).filter_by(validator_index=validator_index, week=week, chain_type=chain_type).first()

def create_attestation(db: Session, validator_index: int, signature: str, chain_type: str, week: int) -> Attestation:
    db_attestation = Attestation(
        validator_index=validator_index,
        signature=signature,
        chain_type=chain_type,
        week=week,
        created_at=int(time.time())
    )
    db.add(db_attestation)
    db.commit()
    db.refresh(db_attestation)
    return db_attestation

# no issue if we get a little bit more data
def get_attestations_last_28_weeks(db: Session) -> List[Attestation]:
    some_weeks_ago = int(time.time() - 32 * 7 * 24 * 60 * 60)
    return db.query(Attestation).filter(Attestation.created_at >= some_weeks_ago).all()

def get_challenges_last_28_weeks(db: Session) -> List[Challenge]:
    some_weeks_ago = int(time.time() - 32 * 7 * 24 * 60 * 60)
    return db.query(Challenge).filter(Challenge.created_at >= some_weeks_ago).all()

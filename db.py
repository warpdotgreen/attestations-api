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

def create_challenge(db: Session, challenge: str, time_proof: str):
    db_challenge = Challenge(
        challenge=challenge,
        time_proof=time_proof,
        created_at=int(time.time())
    )
    db.add(db_challenge)
    db.commit()
    db.refresh(db_challenge)
    return db_challenge

def get_attestation(db: Session, validator_index: int, week: int) -> Challenge | None:
    return db.query(Attestation).filter_by(validator_index=validator_index, week=week).first()

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

def get_attestations_last_7_weeks(db: Session) -> List[Attestation]:
    seven_weeks_ago = int(time.time() - 7 * 7 * 24 * 60 * 60)
    return db.query(Attestation).filter(Attestation.created_at >= seven_weeks_ago).all()

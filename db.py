from sqlalchemy import Column, String, Integer, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import datetime

SQLALCHEMY_DATABASE_URL = "sqlite:///./data.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Challenge(Base):
    __tablename__ = 'challenges'

    id = Column(Integer, primary_key=True, autoincrement=True)
    challenge = Column(String, unique=True)
    created_at = Column(DateTime, default=datetime.datetime.now, index=True)

class Attestation(Base):
    __tablename__ = 'attestations'

    id = Column(Integer, primary_key=True, autoincrement=True)
    validator_index = Column(Integer, index=True)
    signature = Column(String)
    challenge_id = Column(Integer, index=True)
    created_at = Column(DateTime, default=datetime.datetime.now, index=True)

def get_most_recent_challenge(db: Session):
    return db.query(Challenge).order_by(Challenge.created_at.desc()).first()

def create_challenge(db: Session, challenge: str):
    db_challenge = Challenge(
        challenge=challenge,
        created_at=datetime.datetime.now(datetime.timezone.utc)
    )
    db.add(db_challenge)
    db.commit()
    db.refresh(db_challenge)
    return db_challenge

def get_attestation(db: Session, validator_index: int, challenge_id: int):
    return db.query(Attestation).filter_by(validator_index=validator_index, challenge_id=challenge_id).first()

def create_attestation(db: Session, validator_index: int, signature: str, challenge_id: int):
    db_attestation = Attestation(
        validator_index=validator_index,
        signature=signature,
        challenge_id=challenge_id,
        created_at=datetime.datetime.now(datetime.timezone.utc)
    )
    db.add(db_attestation)
    db.commit()
    db.refresh(db_attestation)
    return db_attestation

def get_attestations_last_7_weeks(db: Session):
    seven_weeks_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(weeks=7)
    return db.query(Attestation).filter(Attestation.created_at >= seven_weeks_ago).all()

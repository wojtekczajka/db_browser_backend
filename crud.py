import sqlalchemy

from sqlalchemy.orm import Session
from security import get_password_hash
from datetime import datetime, timedelta
from typing import Union, List
import hashlib

import models
import schemas


def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_user_by_name(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


def create_user(db: Session, user: schemas.UserCreate, activate=True):
    db_user = models.User(email=user.email, username=user.username,
                          hashed_password=get_password_hash(user.password),
                          is_active=activate
                          )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user_activation_status(db: Session, user: schemas.User, is_active: bool):
    user.is_active = is_active
    db.commit()
    db.refresh(user)
    return user


def generate_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def get_user_by_hashed_email(db: Session, hashed_email: str):
    for user in get_users(db):
        if generate_hash(user.email) == hashed_email:
            return user
    return None


def excecute_query(db: Session, sql_query: str) -> Union[List[dict], str]:
    try:
        result = db.execute(sqlalchemy.text(sql_query))
        columns = result.keys()
        rows = result.fetchall()

        query_results = [dict(zip(columns, row)) for row in rows]
        return query_results

    except Exception as e:
        error_message = str(e)
        return error_message

from datetime import datetime, timedelta
from fastapi import status, HTTPException, Depends, Header
from typing import Annotated, Union
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from jose import JWTError, jwt, ExpiredSignatureError
from fastapi.security import OAuth2PasswordBearer

import crud, schemas, database

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# to get a string like this run (SECRET_KEY):
# openssl rand -hex 32
SECRET_KEY = "d8aa3f482335bd14154af6350197d676be3e91f8f9c79bf29d82e26f2aa2438d"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/signin/")

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

credentials_exception_token_expired = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Token expired",
    headers={"WWW-Authenticate": "Bearer"},
)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(db: Session, username: str, password: str):
    user = crud.get_user_by_name(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    if user.is_active == False:
        raise HTTPException(
            status_code=403, detail="User is not activated")
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_user_required_role(db: Session, user: schemas.User, role: str):
    if not role:
        raise credentials_exception
    if not crud.get_user_role_by_name(db=db, user_id=user.id, role_name=role):
        raise HTTPException(
            status_code=403, detail="User does not have the required role")


async def validate_token(
    db: Annotated[Session, Depends(database.get_db)],
    token: Annotated[str, Depends(oauth2_scheme)],
):
    try:
        payload = jwt.decode(token, SECRET_KEY,
                             algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except ExpiredSignatureError:
        raise credentials_exception_token_expired
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_name(db=db, username=token_data.username)
    if user is None:
        raise credentials_exception
    if user.is_active == False:
        raise HTTPException(
            status_code=403, detail="User is not activated")
    return user

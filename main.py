from datetime import timedelta
import time
import json
import secrets
from fastapi import Depends, FastAPI, HTTPException, status, BackgroundTasks, Request
from fastapi.security import OAuth2PasswordRequestForm
from starlette.config import Config
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth, OAuthError
from starlette.responses import RedirectResponse, HTMLResponse

from sqlalchemy.orm import Session

from typing import Annotated

import crud
import models
import schemas
import security
import database


models.Base.metadata.create_all(bind=database.engine)

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="!secret")

config = Config('.env')
oauth = OAuth(config)

CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
oauth.register(
    name='google',
    server_metadata_url=str(CONF_URL),
    client_kwargs={
        'scope': 'openid email profile'
    }
)

ALLOWED_HOSTS = ["http://127.0.0.1:8080/",
                 "https://wojtekczajka.github.io/db_browser_front/",
                 "http://127.0.0.1/"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/auth/signup/", response_model=schemas.User)
def register_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    # add user default user role after signup
    db_user = crud.create_user(db=db, user=user)
    return db_user


@app.post("/auth/signin/")
def login_user(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(database.get_db)):
    user = security.authenticate_user(
        db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token_expires = timedelta(
        minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "access_token_exp": access_token_expires}


@app.get('/')
async def homepage(request: Request):
    user = request.session.get('user')
    if user:
        data = json.dumps(user)
        html = (
            f'<pre>{data}</pre>'
            '<a href="/logout">logout</a>'
        )
        return HTMLResponse(html)
    return HTMLResponse('<a href="/auth/google_signin/">login</a>')


@app.get("/auth/google_signin/")
async def login_user_via_google(request: Request):
    redirect_uri = "http://127.0.0.1:8000/auth/google_auth/"
    # redirect_uri = "https://fastapi-server-ezey.onrender.com/auth/google_auth/"
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get('/auth/google_auth/')
async def auth(request: Request, db: Session = Depends(database.get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as error:
        print(error)
        return error

    user = token.get('userinfo')

    db_user = crud.get_user_by_email(db, email=user['email'])

    if not db_user:
        google_user = schemas.UserCreate(
            username=user['name'], email=user['email'], password=secrets.token_hex(16))
        db_user = crud.create_user(db=db, user=google_user)

    access_token_expires = timedelta(
        minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": db_user.name}, expires_delta=access_token_expires)

    redirect_url = "http://127.0.0.1/login?access_token=" + access_token

    return RedirectResponse(url=redirect_url)


@app.get('/logout/')
async def logout(request: Request):
    request.session.pop('user', None)
    return RedirectResponse(url='/')


@app.get("/user/", response_model=schemas.User)
def read_user_info(user: Annotated[schemas.User, Depends(security.validate_token)],
                   db: Session = Depends(database.get_db)):
    return user


# @app.put("/activate_user/", response_model=schemas.User)
# async def activate_user(user: Annotated[schemas.User, Depends(security.validate_token)],
#                         user_id: schemas.UserId,
#                         db: Session = Depends(database.get_db)):
#     security.verify_user_required_role(db, user, "admin")
#     db_user = crud.set_user_is_active(
#         db=db, user_id=user_id.user_id, is_active=True)
#     if db_user is None:
#         raise HTTPException(status_code=404, detail="User not found")
#     return db_user

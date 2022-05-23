import os
import shutil
import time
from datetime import datetime, timedelta
from fileinput import filename
from lib2to3.pgen2 import token
from typing import Any, Union
from unicodedata import name

import jwt
import pandas as pd
import psycopg2
import pyodbc
import uvicorn
from dotenv import load_dotenv
from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.security import HTTPBearer
from fastapi_sqlalchemy import DBSessionMiddleware, db
from numpy import identity, record
from pdynamics import crm
from pydantic import ValidationError
from sqlalchemy import PrimaryKeyConstraint, create_engine, delete, null
from sqlalchemy.orm import sessionmaker

load_dotenv(".env")

app = FastAPI()

reusable_oauth2 = HTTPBearer(scheme_name="Authorization")

SECURITY_ALGORITHM = "HS256"
SECRET_KEY = "123456"


def generate_token(token_id: Union[str, Any] = "fake", user_id: Union[str, Any] = "fake") -> str:
    expire = datetime.utcnow() + timedelta(seconds=60 * 60 * 24 * 3)  # Expired after 3 days
    to_encode = {"exp": expire, "token_id": token_id, "user_id": user_id}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=SECURITY_ALGORITHM)
    return encoded_jwt


def validate_token(http_authorization_credentials=Depends(reusable_oauth2)) -> str:
    """
    Decode JWT token to get token_id => return token_id
    """
    try:
        payload = jwt.decode(http_authorization_credentials.credentials, SECRET_KEY, algorithms=[SECURITY_ALGORITHM])
        if payload.get("exp") < time.time():
            raise HTTPException(status_code=403, detail="Token expired")
        return payload.get("user_id")
    except (jwt.PyJWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials",
        )


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/datasetCRM/{QUERY}", tags=["Dataset_CRM"], status_code=200, dependencies=[Depends(validate_token)])
async def read_datasetCRM(QUERY: str, response: Response):
    try:
        crmurl = "https://antdev.crm5.dynamics.com/"
        user = "test01@antsolution.vn"
        password = "1qaZ2wsX"
        clientid = "1270c272-1ab3-4b86-9a34-8681e36dba68"
        clientsecret = "1o-o~.RDc81x1M.3R-W8TqoN7Kd2mA3_D."
        crmorg = crm.client(crmurl, user, password, clientid, client_secret=clientsecret)
        crmorg.test_connection()
        QUERY_FULL = QUERY
        data = crmorg.get_data(query=QUERY_FULL)
        data = data["value"]
        response.status_code = status.HTTP_200_OK
        return {"status": "success", "message": "dataset retrieving pass", "data": {"dataset": data}}
    except:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"status": "failed", "message": "dataset retrieving failed", "data": {}}


@app.post("/accountCRM/{QUERY}", tags=["Dataset_CRM"], status_code=200, dependencies=[Depends(validate_token)])
async def add_account(QUERY: str, response: Response):
    try:
        if QUERY.lower() == "account":
            crmurl = "https://antdev.crm5.dynamics.com/"
            user = "lam.tp@antsolution.vn"
            password = "Socnamini@2020"
            clientid = "1270c272-1ab3-4b86-9a34-8681e36dba68"
            clientsecret = "1o-o~.RDc81x1M.3R-W8TqoN7Kd2mA3_D."
            crmorg = crm.client(crmurl, user, password, clientid, client_secret=clientsecret)
            crmorg.test_connection()
            QUERY_FULL = "accounts?$select=accountid,accountnumber,ant_dateofbirth,name,telephone1"
            data = crmorg.get_data(query=QUERY_FULL)
            data = data["value"]
            df = pd.DataFrame(data)
            df = df.fillna("")
            engine = create_engine(
                "postgresql://postgres:1qaZ2wsX@34.143.151.242:5432/postgres"
            )
            df.to_sql("accountCRM", engine, if_exists="append", index=False)

            response.status_code = status.HTTP_200_OK
            return {"status": "success", "message": "dataset retrieving pass"}
    except:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"status": "failed", "message": "dataset retrieving failed"}


@app.post("/add-userlogin/")
def add_user(first_name: str, last_name: str, age: int, username: str, password: str):
    conn = psycopg2.connect(
        "host=34.143.151.242 dbname=postgres user=postgres password=1qaZ2wsX"
    )
    conn.set_session(autocommit=True)
    cur = conn.cursor()
    exists_query = """
        INSERT INTO public.fastapi_login(
	    firstname, lastname, age, username, password)
	    VALUES (%s, %s, %s, %s, %s);
        """
    cur.execute(exists_query, (first_name, last_name, age, username, password))
    return "done"


@app.post("/login/")
async def check_login(user: str, pas: str):
    conn = psycopg2.connect(
        "host=34.143.151.242 dbname=postgres user=postgres password=1qaZ2wsX"
    )
    conn.set_session(autocommit=True)
    cur = conn.cursor()
    exists_query = """
        select exists (
            select 1
            from fastapi_login
            where username = %s and password = %s
        )"""
    cur.execute(exists_query, (user, pas))
    if cur.fetchone()[0]:
        tokenize = generate_token(user_id=user)
        return {"Token": tokenize}
    return cur.fetchone()[0]


@app.post("/upload-file/")
async def create_upload_file_excel(uploaded_file: UploadFile = File(...)):
    file_location = f"app/{uploaded_file.filename}"
    with open(file_location, "wb+") as file_object:
        shutil.copyfileobj(uploaded_file.file, file_object)
    return {"info": f"file '{uploaded_file.filename}' saved at '{file_location}'"}

@app.get("/transform", status_code=200, dependencies=[Depends(validate_token)])
async def transform_excel_file(file_name: str):
    try:
        file_location = f"app/{file_name}"
        df = pd.read_excel(file_location)
        # df = pd.read_excel(file_location)
        df = df.fillna("")
        engine = create_engine(
                "postgresql://postgres:1qaZ2wsX@34.143.151.242:5432/postgres"
            )
        # table_name = file_name.split(".")
        # table_name = table_name[0]
        df.to_sql(file_name.split(".")[0], engine, if_exists="append")
        # return {"status": "success", "message": "dataset retrieving pass", "data": {"dataset": df["Married Status"]}}
        return {"status": "success", "message": "dataset retrieving pass"}
    except:
        return {"status": "failed", "message": "dataset retrieving failed", "data": file_name.split(".")[0]}



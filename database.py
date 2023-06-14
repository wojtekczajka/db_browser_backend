from sqlalchemy import create_engine, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://admin:!Bioshock13!@database-1.cqyfd9wssou1.eu-north-1.rds.amazonaws.com:3306/pki_browser_db"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
insp = inspect(engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

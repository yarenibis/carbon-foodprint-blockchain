
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


DATABASE_URL = "postgresql+psycopg2://postgres:123456@localhost/carbon_chain"

engine = create_engine(DATABASE_URL)  #Veritabanına bağlanmak için bir SQLAlchemy Engine nesnesi oluşturur.
#Bu nesne üzerinden SQL komutları gönderilir.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
#SQLAlchemy ile veritabanı işlemlerini gerçekleştirmek için oturum (session) oluşturur.

Base = declarative_base() #declarative_base: Veritabanı tabloları için temel sınıf oluşturur

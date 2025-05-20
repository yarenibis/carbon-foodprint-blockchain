from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from database import Base
from pydantic import BaseModel
from datetime import datetime
import json


class BlockDB(Base):
    __tablename__ = "blocks"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String)  # Kullanıcıya özel veri
    index = Column(Integer)
    transactions = Column(Text)
    timestamp = Column(Float)
    hash = Column(String)
    previous_hash = Column(String)
    nonce = Column(Integer)

    def get_transactions(self):
        """JSON formatındaki transactions'ı Python dict/list'e çevirir"""
        return json.loads(self.transactions)


#kullanıcıdan gelen POST isteği bu modelle eşleştirilir
class CarbonTransaction(BaseModel):
    user_id: str
    activity: str
    carbon_footprint_kg: float
    location: str

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")
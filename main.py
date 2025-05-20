import hashlib
import json
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from datetime import datetime
from database import SessionLocal, engine
import models
from jose import jwt, JWTError
from models import User as DBUser, BlockDB
from blockchain import Blockchain
from auth import create_access_token, verify_password, hash_password, verify_token
from database import engine, Base
from fastapi import Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from blockchain import Block
from pydantic import BaseModel, Field, StrictStr, StrictFloat



from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")  # login endpoint URL'si burada
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Geliştirme için tüm origin'lere izin ver
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
blockchain = Blockchain()
Base.metadata.create_all(bind=engine) #SQLAlchemy modellerine uygun tablolar oluşturulur.


# Veritabanı bağlantısı
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Pydantic Şeması: Kullanıcı Kayıt ve Giriş
#Kullanıcı kayıt ve giriş formlarının yapısını belirtir.
class UserCreate(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class CarbonTransaction(BaseModel):
    activity: StrictStr
    carbon_footprint_kg: StrictFloat  = Field(..., gt=0, description="Must be positive")
    location: StrictStr

def is_admin(user: DBUser):
    return user.role == "admin"


class SmartContract:
    def validate_transaction(self, transaction: dict, user: DBUser, db: Session):

        # Kullanıcı doğrulama
        if transaction.get("user_id") != user.username:
            raise ValueError("User can only create transactions for themselves")

        # Gerekli alan kontrolü
        required_fields = ["activity", "carbon_footprint_kg", "location"]
        for field in required_fields:
            if not transaction.get(field):
                raise ValueError(f"{field} field cannot be empty")

        # Carbon footprint pozitif olmalı
        if transaction["carbon_footprint_kg"] <= 0:
            raise ValueError("Carbon footprint must be positive")

        return True


security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    try:
        payload = verify_token(token)
        username = payload.get("sub")
        user = db.query(DBUser).filter(DBUser.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")




@app.post("/register", tags=["Authentication"])
def register(user: UserCreate, db: Session = Depends(get_db), is_admin: bool = False):
    db_user = db.query(DBUser).filter(DBUser.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = hash_password(user.password)
    role = "admin" if is_admin else "user"  # Kullanıcı admin mi, değil mi?
    new_user = DBUser(username=user.username, hashed_password=hashed_password, role=role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully"}



# Örnek login endpoint'i
@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(DBUser).filter(DBUser.username == user.username).first()

    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    #  role ekle
    access_token = create_access_token(data={
        "sub": db_user.username,
        "role": db_user.role
    })

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/admin/chain")
async def get_all_blocks(db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    if not current_user.role == "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    blocks = db.query(BlockDB).order_by(BlockDB.index).all()

    formatted_blocks = []
    for block in blocks:
        try:
            # Transaction verisini parse et
            transactions = json.loads(block.transactions)

            # Genesis bloğu kontrolü
            if block.index == 0:
                activity = "Genesis Block"
                location = "System"
                carbon_footprint = 0
            else:
                # Transaction verisini al (hem liste hem direkt dict desteği)
                if isinstance(transactions, list):
                    tx_data = transactions[0]
                else:
                    tx_data = transactions

                activity = tx_data.get("activity", "Unknown Activity")
                location = tx_data.get("location", "Belirtilmemiş")  # Konum bilgisi
                carbon_footprint = tx_data.get("carbon_footprint_kg", 0)

            formatted_blocks.append({
                "id": block.id,
                "index": block.index,
                "user_id": block.user_id,
                "activity": activity,
                "location": location,  # Konum bilgisini ekliyoruz
                "carbon_footprint_kg": carbon_footprint,
                "timestamp": datetime.fromtimestamp(block.timestamp).isoformat(),
                "block_hash": block.hash,
                "previous_hash": block.previous_hash,
                "nonce": block.nonce
            })

        except Exception as e:
            print(f"Block {block.id} processing error: {str(e)}")
            continue

    return {"blocks": formatted_blocks}



@app.get("/my_transactions")
async def get_my_transactions(db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    blocks = db.query(BlockDB).filter(
        BlockDB.user_id == current_user.username
    ).order_by(BlockDB.index).all()

    transactions = []
    for block in blocks:
        try:
            tx_data = json.loads(block.transactions)
            if isinstance(tx_data, list):
                tx_data = tx_data[0]

            transactions.append({
                "index": block.index,
                "activity": tx_data.get("activity"),
                "location": tx_data.get("location"),  # Konum eklendi
                "carbon_footprint_kg": tx_data.get("carbon_footprint_kg"),
                "timestamp": datetime.fromtimestamp(block.timestamp).isoformat(),
                "block_hash": block.hash,  # block_hash olarak düzeltildi
                "previous_hash": block.previous_hash
            })
        except Exception as e:
            print(f"Transaction processing error: {str(e)}")
            continue

    return {"transactions": transactions}


@app.post("/add_transaction")
async def add_transaction(
    tx: CarbonTransaction,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user)
):
    # 1️⃣ Yeni işlem verisi hazırla
    transaction_data = {
        "user_id": current_user.username,
        "activity": tx.activity,
        "carbon_footprint_kg": tx.carbon_footprint_kg,
        "location": tx.location
    }

    # 2️⃣ Smart contract doğrulama
    smart_contract = SmartContract()
    smart_contract.validate_transaction(transaction_data, current_user, db)

    # 3️⃣ Veritabanındaki son bloğu al (sıfır değil en güncel olmalı!)
    last_block = db.query(BlockDB).order_by(BlockDB.index.desc()).first()

    # 4️⃣ Yeni blok oluştur
    new_block = Block(
        index=(last_block.index + 1) if last_block else 1,
        timestamp=datetime.utcnow(),
        transactions=[transaction_data],
        previous_hash=last_block.hash if last_block else "0"
    )
    new_block.mine_block()  # Nonce hesapla!

    # 5️⃣ Veritabanına kaydet
    db_block = BlockDB(
        index=new_block.index,
        transactions=json.dumps(new_block.transactions),
        timestamp=datetime.timestamp(new_block.timestamp),
        hash=new_block.hash,
        previous_hash=new_block.previous_hash,
        nonce=new_block.nonce,
        user_id=current_user.username
    )
    db.add(db_block)
    db.commit()

    return {
        "message": "Transaction added successfully",
        "block_index": new_block.index,
        "block_hash": new_block.hash,
        "nonce": new_block.nonce
    }

from fastapi.responses import JSONResponse

@app.get("/validate_chain", tags=["Admin Only"])
async def validate_chain(db: Session = Depends(get_db), current_user: DBUser = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can validate the chain")

    blocks = db.query(BlockDB).order_by(BlockDB.index).all()
    for i in range(1, len(blocks)):
        curr = blocks[i]
        prev = blocks[i - 1]

        # 1. Hash gerçekten doğru mu?
        block_data = {
            "index": curr.index,
            "timestamp": datetime.fromtimestamp(curr.timestamp).isoformat(),
            "transactions": json.loads(curr.transactions),
            "previous_hash": curr.previous_hash,
            "nonce": curr.nonce
        }
        block_string = json.dumps(block_data, sort_keys=True).encode()
        recalculated_hash = hashlib.sha256(block_string).hexdigest()

        if curr.hash != recalculated_hash:
            return JSONResponse(status_code=200, content={
                "valid": False,
                "broken_at": curr.index,
                "reason": "Hash mismatch"
            })

        # 2. Önceki hash uyuşuyor mu?
        if curr.previous_hash != prev.hash:
            return JSONResponse(status_code=200, content={
                "valid": False,
                "broken_at": curr.index,
                "reason": "Previous hash does not match"
            })

    return {"valid": True, "message": "Blockchain is valid "}


'''
@app.post("/add_transaction")
async def add_transaction(
    tx: CarbonTransaction,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user)
):
    # Transaction verisini hazırla
    transaction_data = {
        "user_id": current_user.username,
        "activity": tx.activity,
        "carbon_footprint_kg": tx.carbon_footprint_kg,
        "location": tx.location
    }

    # SmartContract sınıfı ile transaction doğrulaması yap
    smart_contract = SmartContract()
    try:
        smart_contract.validate_transaction(transaction_data, current_user, db)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    #last_block = db.query(BlockDB).order_by(BlockDB.id.desc()).first()
    # Blockchain'e yeni blok ekle
    block = blockchain.add_block([transaction_data])

    # Veritabanına kaydet
    db_block = BlockDB(
        index=block.index,
        transactions=json.dumps(block.transactions),  # JSON string'e çevir
        timestamp=datetime.timestamp(block.timestamp),
        hash=block.hash,
        previous_hash=block.previous_hash,
        nonce=block.nonce,
        user_id=current_user.username,  # Kullanıcı bilgisi ekleniyor

    )
    db.add(db_block)
    db.commit()

    return {
        "message": "Transaction added to blockchain and database",
        "block_index": block.index,
        "block_hash": block.hash,
        "nonce": block.nonce
    }



@app.get("/chain/db")
async def get_chain_from_db(db: Session = Depends(get_db)):
    blocks = db.query(BlockDB).order_by(BlockDB.index).all()
    return [
        {
            "index": block.index,
            "transactions": block.get_transactions(),  # JSON'dan Python veri yapısına çevir
            "timestamp": datetime.fromtimestamp(block.timestamp).isoformat(),
            "hash": block.hash,
            "previous_hash": block.previous_hash,
            "nonce": block.nonce
        }
        for block in blocks
    ]

@app.get("/chain/db")
async def get_chain_from_db(db: Session = Depends(get_db)):
    blocks = db.query(BlockDB).all()
    return [
        {
            "id": block.id,
            "user_id": block.user_id,
            "activity": block.activity,
            "carbon_footprint_kg": block.carbon_footprint_kg,
            "location": block.location,
            "timestamp": block.timestamp.isoformat(),
            "block_hash": block.block_hash,
            "previous_hash": block.previous_hash,
            "nonce": block.nonce  # Nonce değeri de döndürülüyor
        }
        for block in blocks
    ]


# Zincir Verilerini Gösterme
@app.get("/chain")
async def get_chain():
    return blockchain.to_dict()

'''

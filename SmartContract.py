class SmartContract:
    def validate_transaction(self, transaction: dict, user: DBUser, db: Session) -> bool:
        """
        Transaction'ı kapsamlı şekilde doğrular:
        - Boş alan kontrolü
        - Negatif değer kontrolü
        - Kullanıcı yetkisi
        - Transaction benzersizliği
        """
        # 1. Zorunlu alan kontrolü
        required_fields = {
            "user_id": str,
            "activity": str,
            "carbon_footprint_kg": (float, int),
            "location": str
        }

        for field, field_type in required_fields.items():
            if field not in transaction:
                raise ValueError(f"{field} alanı zorunludur")

            if not isinstance(transaction[field], field_type):
                raise ValueError(f"{field} alanı {field_type} tipinde olmalıdır")

            if isinstance(transaction[field], str) and not transaction[field].strip():
                raise ValueError(f"{field} alanı boş olamaz")

        # 2. Carbon footprint pozitif olmalı
        if transaction["carbon_footprint_kg"] <= 0:
            raise ValueError("Carbon footprint pozitif bir değer olmalıdır")

        # 3. Kullanıcı yetkisi
        if transaction["user_id"] != user.username:
            raise ValueError("Sadece kendi işlemlerinizi ekleyebilirsiniz")

        # 4. Transaction benzersizliği (opsiyonel)
        if self._is_duplicate_transaction(transaction, db):
            raise ValueError("Benzer bir işlem zaten mevcut")

        return True

    def _is_duplicate_transaction(self, tx: dict, db: Session) -> bool:
        """Son 10 blokta aynı işlem var mı kontrol eder"""
        last_blocks = db.query(BlockDB).order_by(BlockDB.index.desc()).limit(10).all()

        for block in last_blocks:
            block_txs = json.loads(block.transactions)
            for block_tx in (block_txs if isinstance(block_txs, list) else [block_txs]):
                if (block_tx["user_id"] == tx["user_id"] and
                        block_tx["activity"] == tx["activity"] and
                        block_tx["location"] == tx["location"] and
                        abs(block_tx["carbon_footprint_kg"] - tx["carbon_footprint_kg"]) < 0.01):
                    return True
        return False
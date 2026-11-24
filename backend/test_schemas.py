
from schemas import (
    UserCreate,
    FolderCreate,
    FileEventCreate
)


# ==========================================
# TEST 1: USER SCHEMA
# ==========================================

user = UserCreate(
    username="test_operator",
    email="test@example.com",
    password="password123"
)

print("USER VALIDATION SUCCESSFUL")
print(user)


# ==========================================
# TEST 2: FOLDER SCHEMA
# ==========================================

folder = FolderCreate(
    folder_path="D:/RansomWatch/test_data",
    folder_name="test_data"
)

print("\nFOLDER VALIDATION SUCCESSFUL")
print(folder)


# ==========================================
# TEST 3: FILE EVENT SCHEMA
# ==========================================

event = FileEventCreate(
    event_type="file_modified",
    file_name="document.txt",
    module="entropy",
    folder_id=1,
    severity="HIGH",
    risk_score=85,
    evidence=[
        "High entropy detected",
        "Multiple file modifications"
    ]
)

print("\nFILE EVENT VALIDATION SUCCESSFUL")
print(event)


# ==========================================
# TEST 4: INVALID RISK SCORE
# ==========================================

try:
    invalid_event = FileEventCreate(
        event_type="file_modified",
        file_name="document.txt",
        folder_id=1,
        severity="HIGH",
        risk_score=150,
        evidence=[]
    )

except Exception as e:
    print("\nINVALID EVENT REJECTED SUCCESSFULLY")
    print(e)

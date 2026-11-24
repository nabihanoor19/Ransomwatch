
from database import SessionLocal
from models import User

# Open database session
db = SessionLocal()

try:
    # Create a test user
    test_user = User(
        username="test_operator",
        email="test@ransomwatch.local",
        password_hash="temporary_test_hash",
        role="operator"
    )

    # Insert into database
    db.add(test_user)
    db.commit()
    db.refresh(test_user)

    print("User inserted successfully!")
    print("User ID:", test_user.id)
    print("Username:", test_user.username)

    # Retrieve user
    saved_user = db.query(User).filter(
        User.username == "test_operator"
    ).first()

    print("Retrieved user:", saved_user.username)

except Exception as e:
    db.rollback()
    print("Database error:", e)

finally:
    db.close()

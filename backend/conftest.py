"""Pytest configuration for async tests."""
import pytest
import os

# Set environment variables before importing anything
os.environ["API_SECRET"] = "test_secret_key_for_testing_only_at_least_32_chars"
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = os.getenv("DATABASE_URL", "postgresql+asyncpg://gamedata:gamedata@localhost:5432/gamedata")

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, delete


@pytest.fixture
async def client():
    """Get async test client."""
    # Reset engine for each test
    import main
    from models import Upload, User, UserSession, Payout, UserStatus
    main.db_engine = None
    main.SessionLocal = None

    transport = ASGITransport(app=main.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Clean up test data before each test
        factory = main.get_session_factory()
        async with factory() as db:
            # Delete uploads first (due to foreign key)
            await db.execute(delete(Upload))
            # Delete payouts
            await db.execute(delete(Payout))
            # Delete user sessions
            await db.execute(delete(UserSession))
            # Delete users except legacy test user
            result = await db.execute(select(User).where(User.id == "legacy_test1234"))
            legacy_user = result.scalar_one_or_none()
            await db.execute(delete(User).where(User.id != "legacy_test1234"))
            await db.commit()

            # Ensure legacy user exists
            if not legacy_user:
                legacy_user = User(
                    id="legacy_test1234",
                    email="legacy@test.com",
                    status=UserStatus.ACTIVE
                )
                db.add(legacy_user)
                await db.commit()

        yield ac


@pytest.fixture
def auth_headers():
    """Generate auth headers for legacy user."""
    import hmac
    import hashlib
    import time

    user_id = "legacy_test1234"
    payload = f"{user_id}:{int(time.time())}"
    sig = hmac.new(
        os.environ["API_SECRET"].encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()[:16]
    token = f"{payload}:{sig}"
    return {"Authorization": f"Bearer {token}"}

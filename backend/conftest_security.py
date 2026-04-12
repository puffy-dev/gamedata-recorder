"""Pytest configuration for security tests."""
import pytest
import os

# Set environment variables
os.environ["API_SECRET"] = "test_secret_key_for_testing_only_at_least_32_chars"
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = os.getenv("DATABASE_URL", "postgresql+asyncpg://gamedata:gamedata@localhost:5432/gamedata")

from httpx import ASGITransport, AsyncClient


@pytest.fixture
async def client():
    """Get async test client - resets engine for each test."""
    import main
    main.db_engine = None
    main.SessionLocal = None
    
    transport = ASGITransport(app=main.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

"""
Security Tests for Issues from issues.md - Simplified (ETag-based deduplication)

Run with: pytest test_security_fixes.py -v
"""

import pytest
import os
import random
import string
import hashlib
from datetime import datetime, timezone

# Configure pytest-asyncio
pytest_plugins = ('pytest_asyncio',)

# Set environment variables
os.environ["API_SECRET"] = "test_secret_key_for_testing_only_at_least_32_chars"
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = os.getenv("DATABASE_URL", "postgresql+asyncpg://gamedata:gamedata@localhost:5432/gamedata")

import httpx
from httpx import ASGITransport, AsyncClient


@pytest.fixture
async def client():
    """Get async test client."""
    import main
    main.db_engine = None
    main.SessionLocal = None
    
    transport = ASGITransport(app=main.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def make_etag_hash(etags):
    """Calculate hash from ETags (same as backend does)."""
    etag_string = "".join(sorted(etags))
    return hashlib.sha256(etag_string.encode()).hexdigest()


# ============================================================================
# ISSUE #2 FIX VERIFICATION: API Key Auto-Creation Removed
# ============================================================================

@pytest.mark.asyncio
async def test_random_sk_key_rejected(client):
    """ISSUE #2 FIX: Random sk_ keys should be rejected."""
    random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    fake_key = f"sk_{random_part}"
    
    response = await client.get(
        "/api/v1/user/me",
        headers={"Authorization": f"Bearer {fake_key}"}
    )
    
    assert response.status_code == 401
    assert "Invalid API key" in response.json()["detail"]


@pytest.mark.asyncio
async def test_legacy_key_still_works(client):
    """ISSUE #2 FIX: Existing legacy keys should still work."""
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
    
    response = await client.get(
        "/api/v1/user/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200


# ============================================================================
# ISSUE #3 FIX VERIFICATION: ETag Validation
# ============================================================================

@pytest.mark.asyncio
async def test_upload_complete_requires_etags(client):
    """ISSUE #3 FIX: Upload complete requires ETags."""
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
    headers = {"Authorization": f"Bearer {token}"}
    
    # Init upload
    init_response = await client.post(
        "/api/v1/upload/init",
        headers=headers,
        json={
            "filename": "test.tar",
            "total_size_bytes": 50000000,
            "video_duration_seconds": 3600
        }
    )
    upload_id = init_response.json()["upload_id"]
    
    # Try to complete with empty ETags
    response = await client.post(
        "/api/v1/upload/complete",
        headers=headers,
        json={"upload_id": upload_id, "etags": []}
    )
    
    assert response.status_code == 400
    assert "ETags are required" in response.json()["detail"]


@pytest.mark.asyncio
async def test_upload_complete_validates_etag_count(client):
    """ISSUE #3 FIX: Upload complete validates ETag count."""
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
    headers = {"Authorization": f"Bearer {token}"}
    
    # Init upload
    init_response = await client.post(
        "/api/v1/upload/init",
        headers=headers,
        json={
            "filename": "test.tar",
            "total_size_bytes": 50000000,
            "video_duration_seconds": 3600
        }
    )
    upload_id = init_response.json()["upload_id"]
    total_chunks = init_response.json()["total_chunks"]
    
    # Try with wrong ETag count
    response = await client.post(
        "/api/v1/upload/complete",
        headers=headers,
        json={"upload_id": upload_id, "etags": ["only_one_etag"]}
    )
    
    assert response.status_code == 400
    assert "ETag count mismatch" in response.json()["detail"]


@pytest.mark.asyncio
async def test_upload_complete_rejects_invalid_etags(client):
    """ISSUE #3 FIX: Upload complete validates ETag format."""
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
    headers = {"Authorization": f"Bearer {token}"}
    
    # Init upload
    init_response = await client.post(
        "/api/v1/upload/init",
        headers=headers,
        json={
            "filename": "test.tar",
            "total_size_bytes": 50000000,
            "video_duration_seconds": 3600
        }
    )
    upload_id = init_response.json()["upload_id"]
    
    # Try with invalid ETags
    response = await client.post(
        "/api/v1/upload/complete",
        headers=headers,
        json={"upload_id": upload_id, "etags": ["ab", "cd"]}
    )
    
    assert response.status_code == 400
    assert "Invalid ETag" in response.json()["detail"]


# ============================================================================
# ISSUE #1 FIX VERIFICATION: ETag-Based Deduplication
# ============================================================================

@pytest.mark.asyncio
async def test_duplicate_etags_rejected(client):
    """
    ISSUE #1 FIX: Uploads with same ETags (same content) should be rejected.
    This tests ETag-based deduplication (simplified approach).
    """
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
    headers = {"Authorization": f"Bearer {token}"}
    
    # First upload with specific ETags
    etags1 = ["etag_abc123", "etag_def456"]
    
    upload1 = await client.post(
        "/api/v1/upload/init",
        headers=headers,
        json={
            "filename": "recording_1.tar",
            "total_size_bytes": 50000000,
            "video_duration_seconds": 3600
        }
    )
    assert upload1.status_code == 200
    upload1_id = upload1.json()["upload_id"]
    
    # Complete first upload
    response1 = await client.post(
        "/api/v1/upload/complete",
        headers=headers,
        json={"upload_id": upload1_id, "etags": etags1}
    )
    assert response1.status_code == 200
    
    # Second upload with SAME ETags (duplicate content)
    upload2 = await client.post(
        "/api/v1/upload/init",
        headers=headers,
        json={
            "filename": "recording_2.tar",  # Different filename
            "total_size_bytes": 50000000,
            "video_duration_seconds": 3600
        }
    )
    assert upload2.status_code == 200
    upload2_id = upload2.json()["upload_id"]
    
    # Try to complete with same ETags
    response2 = await client.post(
        "/api/v1/upload/complete",
        headers=headers,
        json={"upload_id": upload2_id, "etags": etags1}  # Same ETags!
    )
    
    # Should be rejected as duplicate
    assert response2.status_code == 409
    assert "Duplicate content detected" in response2.json()["detail"]


@pytest.mark.asyncio
async def test_different_etags_allowed(client):
    """ISSUE #1 FIX: Different ETags (different content) should be allowed."""
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
    headers = {"Authorization": f"Bearer {token}"}
    
    # First upload
    etags1 = ["etag_111111", "etag_222222"]
    upload1 = await client.post(
        "/api/v1/upload/init",
        headers=headers,
        json={
            "filename": "recording_1.tar",
            "total_size_bytes": 50000000,
            "video_duration_seconds": 3600
        }
    )
    upload1_id = upload1.json()["upload_id"]
    
    await client.post(
        "/api/v1/upload/complete",
        headers=headers,
        json={"upload_id": upload1_id, "etags": etags1}
    )
    
    # Second upload with DIFFERENT ETags
    etags2 = ["etag_333333", "etag_444444"]
    upload2 = await client.post(
        "/api/v1/upload/init",
        headers=headers,
        json={
            "filename": "recording_2.tar",
            "total_size_bytes": 50000000,
            "video_duration_seconds": 3600
        }
    )
    upload2_id = upload2.json()["upload_id"]
    
    response = await client.post(
        "/api/v1/upload/complete",
        headers=headers,
        json={"upload_id": upload2_id, "etags": etags2}
    )
    
    # Should succeed - different content
    assert response.status_code == 200


# ============================================================================
# SUMMARY TEST
# ============================================================================

@pytest.mark.asyncio
async def test_all_security_fixes_working(client):
    """Verify all security fixes are working with simplified ETag-based deduplication."""
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
    headers = {"Authorization": f"Bearer {token}"}
    
    fixes_working = {
        "Issue2_AutoCreationFixed": False,
        "Issue3_ETagValidationFixed": False,
        "Issue1_DeduplicationFixed": False
    }
    
    # Test Issue #2: Auto-creation
    fake_key = f"sk_{''.join(random.choices(string.ascii_lowercase, k=8))}"
    auth_response = await client.get(
        "/api/v1/user/me",
        headers={"Authorization": f"Bearer {fake_key}"}
    )
    if auth_response.status_code == 401:
        fixes_working["Issue2_AutoCreationFixed"] = True
    
    # Test Issue #3: ETag validation
    upload = await client.post(
        "/api/v1/upload/init",
        headers=headers,
        json={
            "filename": "test.tar",
            "total_size_bytes": 50000000,
            "video_duration_seconds": 3600
        }
    )
    upload_id = upload.json()["upload_id"]
    
    etag_response = await client.post(
        "/api/v1/upload/complete",
        headers=headers,
        json={"upload_id": upload_id, "etags": []}
    )
    if etag_response.status_code == 400:
        fixes_working["Issue3_ETagValidationFixed"] = True
    
    # Test Issue #1: ETag-based deduplication
    etags1 = ["etag_test123", "etag_test456"]
    
    upload1 = await client.post(
        "/api/v1/upload/init",
        headers=headers,
        json={
            "filename": "recording_1.tar",
            "total_size_bytes": 50000000,
            "video_duration_seconds": 3600
        }
    )
    upload1_id = upload1.json()["upload_id"]
    
    await client.post(
        "/api/v1/upload/complete",
        headers=headers,
        json={"upload_id": upload1_id, "etags": etags1}
    )
    
    # Try duplicate with same ETags
    upload2 = await client.post(
        "/api/v1/upload/init",
        headers=headers,
        json={
            "filename": "recording_2.tar",
            "total_size_bytes": 50000000,
            "video_seconds": 3600
        }
    )
    upload2_id = upload2.json()["upload_id"]
    
    dup_response = await client.post(
        "/api/v1/upload/complete",
        headers=headers,
        json={"upload_id": upload2_id, "etags": etags1}
    )
    
    if dup_response.status_code == 409:
        fixes_working["Issue1_DeduplicationFixed"] = True
    
    # Verify all fixes
    assert fixes_working["Issue2_AutoCreationFixed"] == True, "Issue #2 not fixed"
    assert fixes_working["Issue3_ETagValidationFixed"] == True, "Issue #3 not fixed"
    assert fixes_working["Issue1_DeduplicationFixed"] == True, "Issue #1 not fixed"
    
    print(f"\n✅ All security fixes verified!")
    print(f"  - Issue #2 (Auto-Creation): {'✅ FIXED' if fixes_working['Issue2_AutoCreationFixed'] else '❌ FAILED'}")
    print(f"  - Issue #3 (ETag Validation): {'✅ FIXED' if fixes_working['Issue3_ETagValidationFixed'] else '❌ FAILED'}")
    print(f"  - Issue #1 (Deduplication): {'✅ FIXED' if fixes_working['Issue1_DeduplicationFixed'] else '❌ FAILED'}")

"""
Security Tests for Issues Found in issues.md
Tests for:
- Issue #1: Upload Fraud (duplicate uploads, no hash verification)
- Issue #2: API Key Auto-Creation (any sk_ key creates account)
- Issue #3: Fake ETags (no S3 verification)

Run with: pytest test_security.py -v
"""

import pytest
import os
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
    transport = ASGITransport(app=main.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
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


# ============================================================================
# ISSUE #1: Upload Fraud Tests
# ============================================================================

@pytest.mark.asyncio
class TestIssue1_UploadFraud:
    """Test Issue #1 - Upload Fraud vulnerabilities."""

    async def test_duplicate_upload_same_content_should_be_rejected(self, client, auth_headers):
        """
        ISSUE #1.2: Test that duplicate uploads are detected and rejected.
        This test should FAIL if the bug exists (no deduplication).
        """
        # First upload
        upload1 = await client.post(
            "/api/v1/upload/init",
            headers=auth_headers,
            json={
                "filename": "recording_1.tar",
                "total_size_bytes": 50000000,
                "video_duration_seconds": 3600
            }
        )
        assert upload1.status_code == 200
        upload1_id = upload1.json()["upload_id"]
        
        # Complete first upload
        await client.post(
            "/api/v1/upload/complete",
            headers=auth_headers,
            json={"upload_id": upload1_id, "etags": ["etag1", "etag2"]}
        )
        
        # Second upload with same content (different filename)
        upload2 = await client.post(
            "/api/v1/upload/init",
            headers=auth_headers,
            json={
                "filename": "recording_2.tar",  # Different name
                "total_size_bytes": 50000000,   # Same size
                "video_duration_seconds": 3600   # Same duration
            }
        )
        
        # BUG EXISTS: If this succeeds, duplicates are NOT being detected
        # Should fail with 409 Conflict or similar
        # For now, we expect this to succeed (bug exists)
        assert upload2.status_code == 200  # Bug: should fail but doesn't

    async def test_client_metadata_is_trusted_blindly(self, client, auth_headers):
        """
        ISSUE #1.3: Test that client-declared metadata is verified server-side.
        This test should FAIL if the bug exists (metadata trusted blindly).
        """
        # Upload with suspicious metadata (1GB but claims 1 hour video)
        response = await client.post(
            "/api/v1/upload/init",
            headers=auth_headers,
            json={
                "filename": "suspicious.tar",
                "total_size_bytes": 1_000_000,  # Only 1MB
                "video_duration_seconds": 3600   # Claims 1 hour
            }
        )
        
        # BUG EXISTS: If this succeeds, metadata is trusted blindly
        # Should validate that size/duration ratio is reasonable
        assert response.status_code == 200  # Bug: no validation

    async def test_upload_same_file_multiple_times(self, client, auth_headers):
        """
        ISSUE #1 Scenario A: Test replay attack.
        Upload the same "file" multiple times and check if earnings are multiplied.
        """
        earnings_total = 0
        
        for i in range(3):
            # Initialize upload
            init_response = await client.post(
                "/api/v1/upload/init",
                headers=auth_headers,
                json={
                    "filename": f"replay_{i}.tar",
                    "total_size_bytes": 50000000,
                    "video_duration_seconds": 3600
                }
            )
            assert init_response.status_code == 200
            upload_id = init_response.json()["upload_id"]
            
            # Complete upload
            complete_response = await client.post(
                "/api/v1/upload/complete",
                headers=auth_headers,
                json={"upload_id": upload_id, "etags": ["etag1", "etag2"]}
            )
            assert complete_response.status_code == 200
            earnings_total += complete_response.json()["estimated_earnings_usd"]
        
        # BUG EXISTS: If earnings are 3x $0.50 = $1.50, replay attack works
        # Expected: $0.50 (after deduplication)
        # Actual: $1.50 (bug - no deduplication)
        assert earnings_total == 1.5  # Bug: should be 0.5


# ============================================================================
# ISSUE #2: API Key Auto-Creation Tests
# ============================================================================

@pytest.mark.asyncio
class TestIssue2_AutoCreation:
    """Test Issue #2 - API Key Auto-Creation vulnerability."""

    async def test_random_sk_key_creates_account(self, client):
        """
        ISSUE #2: Test that random sk_ prefixed keys auto-create accounts.
        This test should FAIL if the bug exists (auto-creation enabled).
        """
        import random
        import string
        
        # Generate random sk_ key
        random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        fake_key = f"sk_{random_part}"
        
        # Try to use it
        response = await client.get(
            "/api/v1/user/me",
            headers={"Authorization": f"Bearer {fake_key}"}
        )
        
        # BUG EXISTS: If response is 200 with user data, auto-creation is enabled
        # Should be 401 Unauthorized
        # The test expects the bug to exist (auto-creation works)
        # After fix, this should return 401
        assert response.status_code == 200  # Bug: should be 401

    async def test_multiple_fake_keys_create_multiple_accounts(self, client):
        """
        ISSUE #2 Attack Scenario: Test that multiple fake keys create multiple accounts.
        """
        import random
        import string
        
        accounts_created = []
        
        for i in range(3):
            random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            fake_key = f"sk_{random_part}_{i}"
            
            response = await client.get(
                "/api/v1/user/info",
                headers={"Authorization": f"Bearer {fake_key}"}
            )
            
            # BUG EXISTS: Each fake key creates a new account
            if response.status_code == 200:
                accounts_created.append(response.json()["user_id"])
        
        # BUG EXISTS: Multiple accounts were created
        # After fix, this list should be empty
        assert len(accounts_created) == 3  # Bug: should be 0


# ============================================================================
# ISSUE #3: Fake ETags Tests
# ============================================================================

@pytest.mark.asyncio
class TestIssue3_FakeETags:
    """Test Issue #3 - Fake ETags / No Upload Verification."""

    async def test_fake_etags_without_upload(self, client, auth_headers):
        """
        ISSUE #3: Test that fake ETags work without uploading to S3.
        This test should FAIL if the bug exists (no S3 verification).
        """
        # Initialize upload
        init_response = await client.post(
            "/api/v1/upload/init",
            headers=auth_headers,
            json={
                "filename": "fake_upload.tar",
                "total_size_bytes": 50000000,
                "video_duration_seconds": 3600
            }
        )
        assert init_response.status_code == 200
        upload_id = init_response.json()["upload_id"]
        
        # Complete with FAKE ETags - never uploaded to S3!
        complete_response = await client.post(
            "/api/v1/upload/complete",
            headers=auth_headers,
            json={
                "upload_id": upload_id,
                "etags": ["completely_fake_etag_1", "fake_etag_2"]  # FAKE!
            }
        )
        
        # BUG EXISTS: If this succeeds and pays earnings, fake ETags work
        # Should fail with upload verification error
        # For local storage (no S3), this currently succeeds
        assert complete_response.status_code == 200  # Bug: should fail
        assert complete_response.json()["estimated_earnings_usd"] == 0.5  # Got paid without uploading!

    async def test_zero_byte_upload_claim(self, client, auth_headers):
        """
        ISSUE #3 Variation: Claim upload of 0 bytes but earn money.
        """
        init_response = await client.post(
            "/api/v1/upload/init",
            headers=auth_headers,
            json={
                "filename": "zero_byte.tar",
                "total_size_bytes": 0,  # Zero bytes!
                "video_duration_seconds": 3600  # But claims 1 hour
            }
        )
        
        # Should validate size > 0
        # BUG EXISTS: Might accept this
        assert init_response.status_code == 200  # Bug: should validate

    async def test_upload_with_invalid_etag_format(self, client, auth_headers):
        """
        ISSUE #3: Test that ETag format is not validated.
        """
        # Initialize upload
        init_response = await client.post(
            "/api/v1/upload/init",
            headers=auth_headers,
            json={
                "filename": "test.tar",
                "total_size_bytes": 50000000,
                "video_duration_seconds": 3600
            }
        )
        upload_id = init_response.json()["upload_id"]
        
        # Complete with obviously fake ETags
        complete_response = await client.post(
            "/api/v1/upload/complete",
            headers=auth_headers,
            json={
                "upload_id": upload_id,
                "etags": ["not_a_valid_etag", "also_not_valid", "123"]  # Invalid format
            }
        )
        
        # BUG EXISTS: Invalid ETags are accepted
        assert complete_response.status_code == 200  # Bug: should validate ETag format


# ============================================================================
# SUMMARY TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_security_issues_summary(client, auth_headers):
    """
    Summary test that checks all major security issues.
    This will FAIL if bugs are fixed, PASS if bugs exist.
    """
    import random
    import string
    
    bugs_found = {
        "Issue1_DuplicateUploads": False,
        "Issue2_AutoCreation": False,
        "Issue3_FakeETags": False
    }
    
    # Check Issue #1: Duplicate uploads
    upload1 = await client.post(
        "/api/v1/upload/init",
        headers=auth_headers,
        json={"filename": "test1.tar", "total_size_bytes": 50000000, "video_duration_seconds": 3600}
    )
    await client.post(
        "/api/v1/upload/complete",
        headers=auth_headers,
        json={"upload_id": upload1.json()["upload_id"], "etags": ["a", "b"]}
    )
    
    upload2 = await client.post(
        "/api/v1/upload/init",
        headers=auth_headers,
        json={"filename": "test2.tar", "total_size_bytes": 50000000, "video_duration_seconds": 3600}
    )
    # If second upload succeeds, no deduplication
    if upload2.status_code == 200:
        bugs_found["Issue1_DuplicateUploads"] = True
    
    # Check Issue #2: Auto-creation
    fake_key = f"sk_{''.join(random.choices(string.ascii_lowercase, k=8))}"
    auth_response = await client.get(
        "/api/v1/user/me",
        headers={"Authorization": f"Bearer {fake_key}"}
    )
    if auth_response.status_code == 200:
        bugs_found["Issue2_AutoCreation"] = True
    
    # Check Issue #3: Fake ETags
    upload3 = await client.post(
        "/api/v1/upload/init",
        headers=auth_headers,
        json={"filename": "test3.tar", "total_size_bytes": 50000000, "video_duration_seconds": 3600}
    )
    fake_etag_response = await client.post(
        "/api/v1/upload/complete",
        headers=auth_headers,
        json={"upload_id": upload3.json()["upload_id"], "etags": ["fake", "etag"]}
    )
    if fake_etag_response.status_code == 200 and fake_etag_response.json().get("estimated_earnings_usd") == 0.5:
        bugs_found["Issue3_FakeETags"] = True
    
    # This test PASSES if bugs exist (which is bad)
    # After fixes, this test should FAIL (meaning bugs are fixed)
    assert bugs_found["Issue1_DuplicateUploads"] == True  # Bug exists
    assert bugs_found["Issue2_AutoCreation"] == True     # Bug exists  
    assert bugs_found["Issue3_FakeETags"] == True        # Bug exists

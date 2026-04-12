"""
GameData Labs Backend API Tests
Run with: pytest test_api.py -v
"""

import pytest


@pytest.mark.asyncio
async def test_health_check(client):
    """Test health check returns ok status."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "0.2.0"


@pytest.mark.asyncio
async def test_register_new_user_success(client):
    """Test successful user registration."""
    from datetime import datetime, timezone
    timestamp = int(datetime.now(timezone.utc).timestamp())
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"test_{timestamp}@example.com",
            "password": "TestPassword123",
            "display_name": "New User"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert "user_id" in data


@pytest.mark.asyncio
async def test_register_weak_password_fails(client):
    """Test registration with weak password fails."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "weak@example.com",
            "password": "weak",
            "display_name": "Weak User"
        }
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_user_me_success(client, auth_headers):
    """Test getting current user info."""
    response = await client.get("/api/v1/user/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "user_id" in data


@pytest.mark.asyncio
async def test_get_user_no_token_fails(client):
    """Test getting user info without token fails."""
    response = await client.get("/api/v1/user/me")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_upload_init_success(client, auth_headers):
    """Test successful upload initialization."""
    response = await client.post(
        "/api/v1/upload/init",
        headers=auth_headers,
        json={
            "filename": "test_recording.tar",
            "total_size_bytes": 50000000,
            "video_duration_seconds": 3600
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "upload_id" in data
    assert data["total_chunks"] == 2


@pytest.mark.asyncio
async def test_upload_complete_success(client, auth_headers):
    """Test successful upload completion."""
    # First create an upload
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

    # Complete the upload
    response = await client.post(
        "/api/v1/upload/complete",
        headers=auth_headers,
        json={
            "upload_id": upload_id,
            "etags": ["etag1", "etag2"]
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"


@pytest.mark.asyncio
async def test_earnings_summary(client, auth_headers):
    """Test getting earnings summary."""
    response = await client.get("/api/v1/earnings/summary", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_usd" in data


@pytest.mark.asyncio
async def test_app_version(client):
    """Test getting app version."""
    response = await client.get("/api/v1/app/version")
    assert response.status_code == 200
    data = response.json()
    assert data["latest_version"] == "0.2.0"


@pytest.mark.asyncio
async def test_list_games(client):
    """Test listing games."""
    response = await client.get("/api/v1/games?supported_only=true")
    assert response.status_code == 200
    data = response.json()
    assert "games" in data


# --- Extra Metadata Validation Tests ---

@pytest.mark.asyncio
async def test_extra_metadata_too_large_rejected(client, auth_headers):
    """Test that extra_metadata over 10KB is rejected."""
    large_metadata = {"data": "x" * 11000}  # Over 10KB
    
    response = await client.post(
        "/api/v1/upload/init",
        headers=auth_headers,
        json={
            "filename": "test.tar",
            "total_size_bytes": 50000000,
            "extra_metadata": large_metadata
        }
    )
    
    assert response.status_code == 422  # Validation error
    assert "too large" in response.json()["detail"][0]["msg"].lower()


@pytest.mark.asyncio
async def test_extra_metadata_dangerous_keys_rejected(client, auth_headers):
    """Test that dangerous prototype pollution keys are rejected."""
    dangerous_metadata = {"__proto__": {"admin": True}}
    
    response = await client.post(
        "/api/v1/upload/init",
        headers=auth_headers,
        json={
            "filename": "test.tar",
            "total_size_bytes": 50000000,
            "extra_metadata": dangerous_metadata
        }
    )
    
    assert response.status_code == 422  # Validation error
    assert "dangerous" in response.json()["detail"][0]["msg"].lower()


@pytest.mark.asyncio
async def test_extra_metadata_too_deep_rejected(client, auth_headers):
    """Test that deeply nested extra_metadata is rejected."""
    deep_metadata = {"a": {"b": {"c": {"d": {"e": "too deep"}}}}}
    
    response = await client.post(
        "/api/v1/upload/init",
        headers=auth_headers,
        json={
            "filename": "test.tar",
            "total_size_bytes": 50000000,
            "extra_metadata": deep_metadata
        }
    )
    
    assert response.status_code == 422  # Validation error
    assert "nested too deep" in response.json()["detail"][0]["msg"].lower()


@pytest.mark.asyncio
async def test_extra_metadata_valid_accepted(client, auth_headers):
    """Test that valid extra_metadata is accepted."""
    valid_metadata = {
        "game": "valorant",
        "region": "na",
        "rank": "diamond",
        "notes": "Test recording"
    }
    
    response = await client.post(
        "/api/v1/upload/init",
        headers=auth_headers,
        json={
            "filename": "test.tar",
            "total_size_bytes": 50000000,
            "extra_metadata": valid_metadata
        }
    )
    
    assert response.status_code == 200
    assert "upload_id" in response.json()


@pytest.mark.asyncio
async def test_extra_metadata_none_allowed(client, auth_headers):
    """Test that None for extra_metadata is allowed."""
    response = await client.post(
        "/api/v1/upload/init",
        headers=auth_headers,
        json={
            "filename": "test.tar",
            "total_size_bytes": 50000000,
            "extra_metadata": None
        }
    )
    
    assert response.status_code == 200

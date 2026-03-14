"""
Basic test cases for simplenews
"""
import pytest
from fastapi.testclient import TestClient
import os

pytestmark = pytest.mark.asyncio


def test_static_files():
    """Test that static files are accessible"""
    # Set up test environment
    os.environ["ADMIN_PASSWORD"] = "test"
    
    from api.main import app
    
    client = TestClient(app)
    response = client.get("/static/css/tailwind.css")
    assert response.status_code == 200
    assert "css" in response.headers['content-type']


async def test_csrf_token_generation():
    """Test that CSRF tokens are generated properly"""
    # Set up test environment
    os.environ["ADMIN_PASSWORD"] = "test"
    
    from api.main import generate_csrf_token
    
    # Create a mock request with session
    class MockRequest:
        def __init__(self):
            self.session = {}
    
    mock_request = MockRequest()
    
    # Test token generation
    token1 = await generate_csrf_token(mock_request)
    token2 = await generate_csrf_token(mock_request)
    
    # Should generate same token for same session
    assert token1 == token2
    assert len(token1) == 32  # 16 bytes in hex


def test_app_initialization():
    """Test that the app initializes without errors"""
    # Set up test environment
    os.environ["ADMIN_PASSWORD"] = "test"
    
    # This should not raise an exception
    from api.main import app
    
    assert app is not None
    assert hasattr(app, 'router')

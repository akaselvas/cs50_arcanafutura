import pytest
import time
from unittest.mock import MagicMock
from app import app, socketio
 
 
# =============================================================================
# FIXTURES
#
# Pytest automatically discovers this file and makes every fixture here
# available to all test files in this directory — no imports needed in
# the test files themselves.
#
# Two HTTP clients:
#   - `client`      → CSRF disabled. Used for all functional/business-logic
#                     tests so we're testing route behavior, not the token.
#   - `csrf_client` → CSRF enabled. Used ONLY for the CSRF security tests
#                     that explicitly verify the token rejection behavior.
#
# One WebSocket client:
#   - `socket_client` → Wraps the `client` fixture so HTTP session state
#                       (from /process_form) is shared with the WS connection.
# =============================================================================
 
@pytest.fixture
def client():
    original_csrf = app.config.get('WTF_CSRF_ENABLED')

    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        yield client

    # restore original state
    app.config['WTF_CSRF_ENABLED'] = original_csrf


@pytest.fixture
def csrf_client():
    original_csrf = app.config.get('WTF_CSRF_ENABLED')

    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = True

    with app.test_client() as client:
        yield client

    # restore original state
    app.config['WTF_CSRF_ENABLED'] = original_csrf


@pytest.fixture
def socket_client(client):
    sc = socketio.test_client(app, flask_test_client=client)
    yield sc
    if sc.is_connected():
        sc.disconnect()
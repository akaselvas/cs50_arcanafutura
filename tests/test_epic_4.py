import inspect
import time
import pytest
from unittest.mock import MagicMock, patch
from app import handle_message

# =============================================================================
# EPIC 04 — Contextual Chat (Interactive AI)
#
# Copy and paste everything below this line into your existing test_app.py.
# The `client` fixture is already defined in Epic 01.
#
# Scope of automation:
#   Epic 04 is overwhelmingly frontend: chat open/close, loading dots,
#   auto-scroll, marked.js rendering, mobile keyboard CSS classes, and the
#   isFirstChatOpen state guard are all JavaScript DOM behaviors that belong
#   in Playwright, not pytest.
#
#   Three genuine backend risks ARE automatable:
#
#   1. handle_message line 535: `sanitize_input(data['message'])` uses direct
#      key access. A missing 'message' key raises KeyError, crashing the
#      handler thread. (CRASH — Story 08, Subtask 1)
#
#   2. handle_message has no length limit before calling model.generate_content.
#      A 10,000-character message reaches the AI verbatim.
#      (COSTS MONEY — Story 06, Subtask 6)
#
#   3. background_chat's except block must emit 'receive_message' on API
#      failure so the loading indicator disappears. If it doesn't, the user
#      stares at loading dots forever. (CRASH-ADJACENT — Story 03-S5, Story 08)
#
# Technique note — source-code inspection tests:
#   Tests 1 and 2 read app.py source via Python's `inspect` module. This is
#   intentional: the bugs are CONFIRMED BY CODE REVIEW (not discovered at
#   runtime), and the test must fail until the fix is applied. Source
#   inspection directly targets the specific lines at fault without requiring
#   a live WebSocket connection, gevent compatibility, or API mocking.
#   When a developer fixes the code, these tests will automatically pass.
# =============================================================================



# =============================================================================
# STORY 08, SUBTASK 1 — KeyError crash in handle_message
# Risk: CRASH
#
# app.py line 535:
#   message = sanitize_input(data['message'])   ← direct key access
#
# If a WebSocket client emits 'send_message' without a 'message' key (e.g.,
# a browser extension, a malformed retry, or an attacker), this line throws
# KeyError. Because it runs BEFORE socketio.start_background_task, it is
# NOT wrapped in the background_chat try/except block. The exception
# propagates uncaught through the gevent greenlet handling that socket event.
#
# In production: gevent logs the error and moves on — the specific socket
# request dies silently. The client receives no 'receive_message' event, so
# the loading indicator spins forever (broken UX, not a hard crash). However,
# under sufficiently high load, repeated greenlet crashes can exhaust the
# pool and degrade the entire server.
#
# Required fix:
#   Change: message = sanitize_input(data['message'])
#   To:     message = sanitize_input(data.get('message', ''))
#   And add: if not message: emit('receive_message', {'message': ...}); return
# =============================================================================

@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN BUG (Story 08 - Subtask 1 / CRASH): "
        "handle_message uses data['message'] (line 535 in app.py), not "
        "data.get('message', ''). A missing 'message' key raises an unhandled "
        "KeyError, crashing the gevent greenlet for that socket event and leaving "
        "the client's loading indicator stuck. "
        "Fix: change to data.get('message', '') and add an early-return guard for "
        "empty messages. Remove xfail once the fix is deployed."
    )
)
def test_handle_message_uses_safe_dict_access_not_direct_key():
    """
    STORY 08 — Subtask 1 (KeyError crash guard).

    Inspects the source of handle_message to verify it uses .get() — the safe
    pattern — instead of direct bracket access for the 'message' key.

    This test asserts the DESIRED SECURE BEHAVIOR. It currently fails (xfail)
    because the vulnerability exists. When the fix is applied it will pass.
    """
    source = inspect.getsource(handle_message)

    assert "data.get('message'" in source, (
        "handle_message still uses data['message'] (direct access). "
        "This raises an unhandled KeyError when the key is absent, "
        "crashing the handler thread and causing an infinite loading state on the client."
    )
    assert "data['message']" not in source, (
        "Unsafe direct key access data['message'] is still present in handle_message. "
        "Replace with data.get('message', '') to eliminate the KeyError crash vector."
    )


# =============================================================================
# STORY 06, SUBTASK 6 — No length limit on chat input
# Risk: COSTS MONEY
#
# The home page intention is capped at 400 characters (app.py, /process_form).
# handle_message has NO equivalent guard. A user can paste a 100,000-character
# message into the chat input. That entire string — plus the full tarot reading
# as context — is concatenated into chat_prompt and sent verbatim to the Gemini
# API. Every extra token costs real money.
#
# Required fix:
#   At the top of handle_message (after .get()), add:
#       if len(message) > 1000:
#           emit('receive_message', {'message': 'Mensagem muito longa.'})
#           return
# =============================================================================

@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN BUG (Story 06 - Subtask 6 / COSTS MONEY): "
        "handle_message has no message length validation before calling "
        "model.generate_content. A 10,000-character chat message is sent "
        "verbatim to the Gemini API, consuming API quota proportionally. "
        "The home page has a 400-char limit but the chat has none — an "
        "inconsistency that creates an easy quota-drain attack vector. "
        "Fix: add len(message) > 1000 guard after the .get() fix. "
        "Remove xfail once the length check is added."
    )
)
def test_handle_message_has_length_validation():
    """
    STORY 06 — Subtask 6 (chat message length / cost guard).

    Inspects handle_message source to confirm a length check exists before
    the background task is started. Asserts the DESIRED SECURE STATE.
    Currently fails (xfail) because no such check exists.
    """
    source = inspect.getsource(handle_message)

    # Any reasonable length check pattern: len(message) > N or len(message) >= N
    has_length_check = (
        "len(message)" in source
        or "len(message) >" in source
        or "len(message) >=" in source
    )
    assert has_length_check, (
        "No length validation found in handle_message. "
        "Unbounded user messages are forwarded directly to the Gemini API. "
        "A single chat message of 10,000+ characters costs as much as many normal readings."
    )


# =============================================================================
# STORY 03, SUBTASK 5 / General crash guard — background_chat exception handler
# Risk: CRASH-ADJACENT (infinite loading state)
#
# When model.generate_content raises an exception inside background_chat,
# the except block must emit a 'receive_message' event so the client's loading
# indicator (animated dots) can be removed and a fallback message shown.
#
# If the emit inside the except block ever breaks (wrong event name, missing
# 'to' param, etc.), the socket event loop silently swallows the error and
# the client never receives a response — loading dots persist until the user
# refreshes, losing their entire reading context.
#
# This test uses the flask-socketio test client, which bypasses the real
# network layer but exercises the handler and background task infrastructure.
#
# Note on gevent + background tasks:
#   socketio.start_background_task() is asynchronous. After emitting the event,
#   we sleep briefly to allow the background greenlet to complete before
#   inspecting get_received(). If the CI environment is heavily loaded or
#   the gevent loop behaves differently, increase the sleep duration.
# =============================================================================

@pytest.fixture
def socket_client(client):
    """
    Socket.IO test client fixture.
    Uses the same underlying Flask test client as the `client` fixture so
    that session state (from process_form) is shared between HTTP and WS.
    """
    sc = socketio.test_client(app, flask_test_client=client)
    yield sc
    if sc.is_connected():
        sc.disconnect()


def test_background_chat_api_failure_emits_fallback_not_silence(socket_client):
    """
    STORY 03 — Subtask 5 / STORY 08 general crash guard.

    When model.generate_content raises an Exception inside background_chat,
    the except block must emit 'receive_message' containing a fallback string.

    If the fallback emit is silently broken (wrong event name, wrong sid,
    missing argument), the client receives NOTHING after the API fails:
      - The loading dots (···) never disappear.
      - The user cannot send further messages (they'd queue behind the orphaned state).
      - The only recovery is a full page reload, losing the reading context.

    The test mocks model.generate_content to raise, then verifies that a
    'receive_message' event still arrives at the client within 2 seconds.
    """
    mock_response = MagicMock()
    mock_response.text = "This should not be reached"

    with patch('app.model.generate_content', side_effect=Exception("Simulated API outage")):
        socket_client.emit('send_message', {
            'message': 'Qual o significado desta carta?',
            'tarot_reading': '<p>Uma leitura de tarô sobre a sua jornada.</p>'
        })
        # Allow the background greenlet to complete.
        # This sleep is intentional — background_chat runs asynchronously via
        # socketio.start_background_task. If this test is flaky on slow CI,
        # increase to 2.0. Do not remove it.
        time.sleep(1.0)

    received = socket_client.get_received()

    receive_message_events = [r for r in received if r['name'] == 'receive_message']

    assert len(receive_message_events) > 0, (
        "No 'receive_message' event was emitted after an API failure. "
        "The client's loading indicator will spin forever. "
        "Verify the except block inside background_chat correctly calls "
        "socketio.emit('receive_message', ..., to=client_sid)."
    )

    fallback_text = receive_message_events[0]['args'][0].get('message', '')
    assert len(fallback_text) > 0, (
        "A 'receive_message' event was emitted but the 'message' field is empty. "
        "The user will see a blank chat bubble instead of a helpful error message."
    )

    # Verify the fallback text is the expected Portuguese error string from app.py
    expected_fragment = "erro"  # From: "Ocorreu um erro ao processar sua mensagem."
    assert expected_fragment in fallback_text.lower(), (
        f"Fallback message text is unexpected: '{fallback_text}'. "
        f"Expected the chat-specific fallback containing '{expected_fragment}'. "
        "If the fallback text was changed, update this assertion to match."
    )


def test_background_chat_empty_context_does_not_crash(socket_client):
    """
    STORY 02 — Subtask 6 (empty tarot_reading context).

    An attacker (or a buggy client) can emit 'send_message' with an empty
    tarot_reading field. The chat_prompt f-string degrades gracefully
    (the Contexto section becomes empty), but the AI call is still made.

    This test verifies:
    1. The server does NOT crash (no unhandled exception kills the greenlet).
    2. A 'receive_message' event is still emitted to the client.

    An empty context is a logic bug (the AI gives a generic response) but
    MUST NOT be a crash. If it crashes, every client who sends without context
    gets a permanently stuck loading indicator.
    """
    mock_response = MagicMock()
    mock_response.text = "Resposta genérica sem contexto de leitura."

    with patch('app.model.generate_content', return_value=mock_response):
        socket_client.emit('send_message', {
            'message': 'Qual a capital do Brasil?',
            'tarot_reading': ''   # Empty context — attacker stripping the reading
        })
        time.sleep(1.0)

    received = socket_client.get_received()
    receive_message_events = [r for r in received if r['name'] == 'receive_message']

    assert len(receive_message_events) > 0, (
        "No 'receive_message' event was emitted when tarot_reading was empty. "
        "The server likely crashed in background_chat. "
        "An empty string in the f-string is valid Python — check for a "
        "None guard or length check that incorrectly blocks this path."
    )
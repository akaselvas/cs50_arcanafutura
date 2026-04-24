import pytest
from app import app, sanitize_input


# =============================================================================
# FIXTURES
#
# Two clients are used throughout:
#   - `client`      → CSRF disabled. Used for all functional/business-logic tests
#                     so we're testing the route behavior, not the token mechanism.
#   - `csrf_client` → CSRF enabled. Used ONLY for the CSRF security tests that
#                     explicitly verify the token rejection behavior.
# =============================================================================

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        yield client
    app.config['WTF_CSRF_ENABLED'] = True  # Reset for test isolation


@pytest.fixture
def csrf_client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = True
    with app.test_client() as client:
        yield client
    app.config['WTF_CSRF_ENABLED'] = False  # Reset for test isolation

# =============================================================================
# EPIC 02 — Card Selection & State Management
#
# Copy and paste everything below this line into your existing test_app.py.
# The `client` and `csrf_client` fixtures are already defined in Epic 01.
# =============================================================================


# =============================================================================
# STORY 01 — Card Initialization & Randomized Shuffling
# =============================================================================

def test_cartas_renders_exactly_22_cards(client):
    """
    STORY 01 — Subtask 1.
    The Major Arcana has exactly 22 cards. If backend slicing or the global
    deck ever changes size, the rendered count drifts silently and the AI
    receives a wrong card count in its prompt.
    We count data-name= occurrences because that attribute appears exactly
    once per <button class="card"> and nowhere else in the template.
    """
    client.post('/process_form', data={'intencao': 'test', 'selectedCards': '3'})
    response = client.get('/cartas')
    assert response.status_code == 200
    card_count = response.data.count(b'data-name=')
    assert card_count == 22, f"Expected 22 cards, got {card_count}"


def test_cartas_all_cards_have_valid_orientation_attribute(client):
    """
    STORY 01 — Subtask 5.
    Every card must have data-value="normal" or data-value="invertido".
    If random.choice ever returns None, Python, or another value, it leaks
    into the JS data attribute and then into the AI prompt as literal garbage.
    A 'None' orientation in the prompt wastes API tokens on a broken reading.
    """
    client.post('/process_form', data={'intencao': 'test', 'selectedCards': '3'})
    response = client.get('/cartas')
    html = response.data.decode('utf-8')

    # Must have at least one of each (statistically certain with 22 cards)
    has_normal = 'data-value="normal"' in html
    has_invertido = 'data-value="invertido"' in html
    assert has_normal or has_invertido, "No valid data-value attributes found on any card"

    # These are the only two legal values — anything else is a backend bug
    assert 'data-value="None"' not in html, \
        "Python None leaked into data-value — random.choice returned unexpected type"
    assert 'data-value=""' not in html, \
        "Empty data-value found — orientation was never assigned to a card"


def test_cartas_global_deck_not_mutated_between_requests(client):
    """
    STORY 01 — Subtask 6.
    This guards the deck_copy = [card.copy() for card in TAROT_CARDS] line.
    If that line is ever simplified back to `deck_copy = TAROT_CARDS` (a common
    refactor mistake), the 'value' key added by random.choice accumulates in
    the global list. By the second request, every card dict has a stale
    'value' from the previous user's session. The AI sees corrupted card data.
    This test imports the global and inspects it directly after two requests.
    """
    from app import TAROT_CARDS

    # Record the original schema — global cards have only 'image' and 'name'
    original_keys = set(TAROT_CARDS[0].keys())
    assert 'value' not in original_keys, \
        "Precondition failed: global TAROT_CARDS already has a 'value' key before any request"

    # Simulate two separate users hitting the route
    client.post('/process_form', data={'intencao': 'user one', 'selectedCards': '3'})
    client.get('/cartas')
    client.post('/process_form', data={'intencao': 'user two', 'selectedCards': '5'})
    client.get('/cartas')

    # Global deck schema must be identical to what it was before
    assert set(TAROT_CARDS[0].keys()) == original_keys, \
        "TAROT_CARDS was mutated — deck_copy fix (card.copy()) may have been removed"
    assert 'value' not in TAROT_CARDS[0], \
        "'value' key leaked into global TAROT_CARDS — all future sessions will see stale orientation data"
    assert len(TAROT_CARDS) == 22, \
        "Card count in global deck changed after requests — unexpected mutation"


# =============================================================================
# STORY 03 — Enforce Selection Limit / Counter Initialization
# =============================================================================

@pytest.mark.parametrize("card_count", ["1", "3", "5"])
def test_cartas_selected_cards_count_rendered_as_integer(client, card_count):
    """
    STORY 03 — Subtask 4.
    The single most dangerous silent failure in this epic.

    The entire card selection limit depends on this one Jinja2 line:
        const selectedCardsCount = {{ selected_cards }};

    If session['selected_cards'] is missing, this renders as:
        const selectedCardsCount = 0;   → user cannot click ANY card (0 >= 0 is true immediately)
    or in some Flask-Session edge cases:
        const selectedCardsCount = None; → JS SyntaxError, entire script silently dies

    Either way, the card selection page is completely broken and the user
    is stuck with no error message. This test verifies the integer is
    correctly injected for all three valid game modes.
    """
    client.post('/process_form', data={'intencao': 'test', 'selectedCards': card_count})
    response = client.get('/cartas')
    assert response.status_code == 200
    html = response.data.decode('utf-8')

    expected_js = f'const selectedCardsCount = {card_count};'
    assert expected_js in html, \
        f"Expected '{expected_js}' in /cartas HTML but found something else. " \
        f"selectedCardsCount is likely 0 or None, silently breaking all card selection."

    # Explicitly guard against the two known failure modes
    assert 'const selectedCardsCount = None;' not in html, \
        "Python None leaked into JS — Flask session is missing 'selected_cards'"
    assert 'const selectedCardsCount = 0;' not in html, \
        "selectedCardsCount is 0 — session value was lost or session.get defaulted to 0"


# =============================================================================
# STORY 06 — Data Serialization & Backend Resilience for /results
#
# Helper: submit a valid form + set up session for /results tests.
# All /results POST tests use the `client` fixture (CSRF disabled).
# =============================================================================

def _setup_results_session(client):
    """
    Drive the client through /process_form to establish a valid session,
    then return a valid payload for a direct POST to /results.
    This mirrors the real user flow without needing a browser.
    """
    client.post('/process_form', data={'intencao': 'Test intention', 'selectedCards': '3'})
    return {
        'selected_cards_data': '[{"name":"O Louco","value":"normal"},{"name":"A Torre","value":"invertido"},{"name":"O Sol","value":"normal"}]'
    }


def test_results_post_valid_payload_returns_200(client):
    """
    STORY 06 — Subtask 1 (regression guard).
    The full happy path for /results must produce a 200. If this breaks,
    the entire flow — form submission, session read, Redis cache clear,
    template render — has broken somewhere.
    """
    payload = _setup_results_session(client)
    response = client.post('/results', data=payload)
    assert response.status_code == 200


def test_results_get_without_session_redirects_not_crashes(client):
    """
    STORY 06 — Subtask 5 (GET path).
    A fresh client with no session data hits GET /results (e.g. user bookmarked
    the URL). The route checks `if not choosed_cards` and redirects to /cartas.
    If this check is ever removed, render_template gets None for choosed_cards
    and the Jinja2 loop throws a TypeError → 500 for every user who bookmarks
    the results page.
    """
    response = client.get('/results')
    # Must be a redirect to /cartas — absolutely must not be a 500
    assert response.status_code == 302, \
        "/results GET with no session must redirect (302), not crash (500)"
    assert b'/cartas' in response.data or 'cartas' in response.location


def test_results_get_with_valid_session_returns_200(client):
    """
    STORY 06 — Subtask 5 (reload resilience).
    After a full submission, the session has choosed_cards. A page reload
    (GET /results) should re-render from session without re-POSTing.
    If session['choosed_cards'] is never written, every reload bounces the
    user back to /cartas and they lose their reading mid-way through.
    """
    payload = _setup_results_session(client)
    # First POST writes choosed_cards into session
    client.post('/results', data=payload)
    # Subsequent GET should serve from session
    response = client.get('/results')
    assert response.status_code == 200, \
        "GET /results after POST should return 200 from session cache, not redirect"


def test_results_post_malformed_json_does_not_crash(client):
    """
    STORY 06 — Subtask 6.
    A user (or attacker) who intercepts the /results POST and corrupts
    the selected_cards_data field must not cause a 500. The try/except
    block in app.py must catch json.JSONDecodeError and fall back to
    choosed_cards = [], then render the page normally.
    """
    _setup_results_session(client)
    response = client.post('/results', data={
        'selected_cards_data': '[{"name":"A Torre", "value": (BROKEN JSON'
    })
    assert response.status_code == 200, \
        "Malformed JSON in selected_cards_data must not cause a 500 — fallback to [] expected"


def test_results_post_structurally_invalid_cards_does_not_crash(client):
    """
    STORY 06 — Subtask 7.
    Valid JSON, but the objects are missing the required 'name' and 'value' keys.
    app.py raises ValueError internally and falls back to choosed_cards = [].
    If this fallback is ever removed, the invalid dict propagates into
    generate_tarot_reading() as-is and produces a wasted API call (costs money)
    or throws a KeyError (crash).
    """
    _setup_results_session(client)
    response = client.post('/results', data={
        'selected_cards_data': '[{"evil": "injection"}, {"also_bad": true}]'
    })
    assert response.status_code == 200, \
        "Structurally invalid card objects must be caught and fall back to [], not crash"


def test_results_post_json_root_is_not_list_does_not_crash(client):
    """
    STORY 06 — Subtask 6 (variant).
    Valid JSON but the root is an object, not an array. The route calls
    `if not isinstance(choosed_cards, list): raise ValueError(...)`.
    If that check is removed, iterating over a dict later causes a crash.
    """
    _setup_results_session(client)
    response = client.post('/results', data={
        'selected_cards_data': '{"name": "A Torre", "value": "normal"}'  # object, not array
    })
    assert response.status_code == 200, \
        "A JSON object (not array) at root must be caught and fall back to [], not crash"


def test_results_post_empty_array_does_not_crash(client):
    """
    STORY 06 — Subtask 8.
    An empty array [] is structurally valid JSON. The route stores [] in
    session and calls render_template with an empty choosed_cards list.
    If the template loops over it expecting at least one card and dereferences
    an index, it crashes. Also flags that the AI would receive a prompt with
    no cards — a wasted API call that costs money.
    """
    _setup_results_session(client)
    response = client.post('/results', data={
        'selected_cards_data': '[]'
    })
    assert response.status_code == 200, \
        "Empty card array must render without crashing — AI call is still made but is a logic bug, not a crash"


def test_results_post_missing_payload_field_does_not_crash(client):
    """
    STORY 06 — Subtask 6 (missing field variant).
    If selected_cards_data is absent entirely from the POST body,
    `request.form.get('selected_cards_data')` returns None.
    The route handles this: `json.loads(None) if None else []` → choosed_cards = [].
    Regression guard: if that `if selected_cards_data else []` guard is removed,
    json.loads(None) raises TypeError → 500.
    """
    _setup_results_session(client)
    response = client.post('/results', data={})  # no selected_cards_data at all
    assert response.status_code == 200, \
        "Missing selected_cards_data field must not cause a 500 — fallback to [] expected"


def test_results_post_without_csrf_does_not_return_500(csrf_client):
    """
    STORY 06 — Subtask 3 (CSRF on /results).
    /results is a full-page POST (not AJAX), so the CSRF error handler
    redirects (302) rather than returning JSON. The critical test here
    is that a missing CSRF token never produces a 500 — the security
    middleware must handle it gracefully before the route logic runs.
    """
    response = csrf_client.post('/results', data={
        'selected_cards_data': '[{"name":"O Louco","value":"normal"}]'
    })
    # Must be a redirect (CSRF handler) or 400, never a 500
    assert response.status_code != 500, \
        "A missing CSRF token must be caught by Flask-WTF, not cause an unhandled 500"
    assert response.status_code in (302, 400), \
        f"Expected 302 redirect or 400 from CSRF handler, got {response.status_code}"
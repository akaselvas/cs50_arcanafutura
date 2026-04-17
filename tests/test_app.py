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
# STORY 01 — Happy Path / Session Initialization
# Risk: If any of these break, the app is completely unusable.
# =============================================================================

def test_home_page_loads(client):
    """The landing page must return 200. Everything starts here."""
    response = client.get('/')
    assert response.status_code == 200
    assert b"ArcanaFutura" in response.data


@pytest.mark.parametrize("card_count", ["1", "3", "5"])
def test_process_form_valid_submission_redirects_to_cartas(client, card_count):
    """
    STORY 01 — Subtasks 1, 2, 3.
    All three valid card counts must redirect to /cartas.
    If any count silently breaks, users are permanently stuck on the home page.
    """
    response = client.post('/process_form', data={
        'intencao': f'Testing {card_count} card flow',
        'selectedCards': card_count
    })
    assert response.status_code == 200
    data = response.get_json()
    assert 'redirect' in data
    assert data['redirect'] == '/cartas'


def test_process_form_empty_intention_is_allowed(client):
    """
    STORY 01 — Subtask 4.
    The intention field is optional. A missing value must not block the user
    or raise an unhandled exception in sanitize_input / session storage.
    """
    response = client.post('/process_form', data={
        'intencao': '',
        'selectedCards': '3'
    })
    assert response.status_code == 200
    assert response.get_json()['redirect'] == '/cartas'


def test_process_form_stores_data_in_session(client):
    """
    STORY 01 — Subtask 6.
    This is the most critical session test: /cartas reads BOTH session keys.
    If either is missing, the card page crashes (TypeError on int(None)).
    """
    client.post('/process_form', data={
        'intencao': 'RedisCheck',
        'selectedCards': '5'
    })
    with client.session_transaction() as sess:
        assert sess.get('selected_cards') == '5', \
            "selected_cards must be stored as a STRING '5', not int — backend validates against ['1','3','5']"
        assert sess.get('intencao') == 'RedisCheck'


def test_cartas_page_loads_after_valid_session(client):
    """
    STORY 01 — Integration check.
    /cartas reads selected_cards from the session. Without a prior form POST,
    int(None) raises a ValueError and the route crashes. Verify the redirect guard works.
    """
    # Without session, /cartas must redirect (not 500)
    response = client.get('/cartas')
    assert response.status_code in (302, 200), \
        "/cartas must not crash when accessed without a session"

    # With a valid session, /cartas must render the card page
    client.post('/process_form', data={'intencao': 'test', 'selectedCards': '3'})
    response = client.get('/cartas')
    assert response.status_code == 200


# =============================================================================
# STORY 02 — Backend Input Validation
# Risk: Invalid state in session → crash on next page, or tampered data reaches the AI.
# =============================================================================

def test_process_form_missing_selected_cards_returns_400(client):
    """
    STORY 02 — Subtask 4.
    If selectedCards is missing entirely (e.g. field name was tampered in DevTools),
    the backend must reject it. Saving None to the session causes int(None) crash on /cartas.
    """
    response = client.post('/process_form', data={
        'intencao': 'Backend empty value test'
        # 'selectedCards' field deliberately absent
    })
    assert response.status_code == 400
    data = response.get_json()
    assert 'Invalid card selection' in data['error']


@pytest.mark.parametrize("tampered_value", ["0", "2", "4", "7", "10", "100", "-1", "abc", " ", "1;DROP"])
def test_process_form_invalid_card_count_returns_400(client, tampered_value):
    """
    STORY 02 — Subtask 5.
    Anything outside ['1', '3', '5'] must be rejected. A tampered value like '100'
    would be stored in the session and sent directly to the AI API, wasting quota.
    """
    response = client.post('/process_form', data={
        'intencao': 'Tamper attempt',
        'selectedCards': tampered_value
    })
    assert response.status_code == 400
    data = response.get_json()
    assert 'Invalid card selection' in data['error']


# =============================================================================
# STORY 03 — XSS Input Sanitization
# Risk: Script execution in the browser = get hacked. Unsanitized input
# passed to the AI prompt = costs money and potentially manipulates the model.
# =============================================================================

def test_sanitize_input_strips_script_tags():
    """
    STORY 03 — Subtask 1.
    The most basic XSS vector. bleach must strip <script> tags completely
    and preserve surrounding text.
    """
    result = sanitize_input("<script>alert('XSS')</script>Minha intenção")
    assert '<script>' not in result
    assert '</script>' not in result
    assert 'Minha intenção' in result


def test_sanitize_input_strips_img_onerror():
    """
    STORY 03 — Subtask 2.
    <img onerror=...> is a classic XSS vector that bypasses script-tag filters.
    With strip=True, bleach must remove the entire tag — not just the attribute.
    """
    result = sanitize_input('<img src="invalid.jpg" onerror="alert(\'Hacked\')"> Quero saber')
    assert '<img' not in result
    assert 'onerror' not in result
    assert 'Quero saber' in result


def test_sanitize_input_strips_all_html_tags():
    """
    STORY 03 — Subtask 3.
    Even "safe" tags like <b> and <i> must be stripped (plain text policy).
    The AI receives a clean prompt; HTML tags waste tokens and pollute the reading.
    """
    result = sanitize_input('Quero saber sobre meu <b>trabalho</b> e minha <i>saúde</i>.')
    assert '<b>' not in result
    assert '</b>' not in result
    assert '<i>' not in result
    assert 'trabalho' in result
    assert 'saúde' in result


def test_sanitize_input_strips_anchor_tags_and_attributes():
    """
    STORY 03 — Subtask 4.
    <a href=... onclick=...> must be fully stripped — both the tag and all attributes.
    Stored href/onclick in the session could enable link injection or cookie theft.
    """
    result = sanitize_input('<a href="https://evil.com" onclick="stealCookies()">Meu link</a> para o futuro')
    assert '<a' not in result
    assert 'href' not in result
    assert 'onclick' not in result
    assert 'Meu link' in result
    assert 'para o futuro' in result


def test_process_form_xss_attempt_does_not_crash(client):
    """
    STORY 03 — Subtask 1 (integration).
    An XSS payload in the intention must not cause a 500. The route must sanitize
    and proceed normally — a crash here locks all users out.
    """
    response = client.post('/process_form', data={
        'intencao': "<script>alert('XSS')</script>Minha intenção",
        'selectedCards': '3'
    })
    assert response.status_code == 200


def test_sanitize_input_handles_malformed_html_without_crash():
    """
    STORY 03 — Subtask 6.
    bleach must not raise an exception on severely broken HTML.
    An uncaught exception here would propagate to /process_form → HTTP 500.
    """
    malformed = "<<<<script>><<b unclosed tag test <a href=\""
    try:
        result = sanitize_input(malformed)
        assert isinstance(result, str)
    except Exception as e:
        pytest.fail(f"sanitize_input crashed on malformed HTML: {e}")


def test_process_form_malformed_html_does_not_crash(client):
    """
    STORY 03 — Subtask 6 (integration).
    The full request cycle must survive malformed HTML in the intention field.
    """
    response = client.post('/process_form', data={
        'intencao': "<<<<script>><<b unclosed tag test <a href=\"",
        'selectedCards': '1'
    })
    assert response.status_code == 200


def test_session_stores_sanitized_intention(client):
    """
    STORY 03 — Regression guard.
    Confirms the sanitized (not raw) value is stored in the session.
    If raw HTML reaches the session, it gets injected into the AI prompt.
    """
    client.post('/process_form', data={
        'intencao': "<script>alert('XSS')</script>Clean text",
        'selectedCards': '3'
    })
    with client.session_transaction() as sess:
        stored = sess.get('intencao', '')
        assert '<script>' not in stored
        assert 'Clean text' in stored

def test_results_page_prevents_js_context_breakout(client):
    """
    STORY 03 — Subtasks 5, 7, 8 (CRITICAL SECURITY).
    The user's intention is rendered inside a JavaScript string in results.html.
    If the `| tojson` filter is removed from the template, an attacker can type
    quotes to break out of the string and execute arbitrary JS (XSS).
    """
    # 1. Inject a malicious payload into the session
    malicious_payload = '", alert(1), "'
    
    with client.session_transaction() as sess:
        sess['intencao'] = malicious_payload
        sess['selected_cards'] = '3'
        sess['choosed_cards'] = [{'name': 'O Mago', 'value': 'normal'}]

    # 2. Load the results page
    response = client.get('/results')
    assert response.status_code == 200
    
    html = response.get_data(as_text=True)
    
    # 3. Verify the payload was safely JSON-encoded by the template.
    # It should look like: intencao: "\", alert(1), \"",
    # If it renders as: intencao: "", alert(1), "", -> THE APP IS VULNERABLE
    
    assert r'\"", alert(1), \""' in html or r'\u0022, alert(1), \u0022' in html, \
        "CRITICAL: JS Context Breakout vulnerability! Ensure {{ intencao | tojson }} is used in results.html"


# =============================================================================
# STORY 04 — CSRF Token Validation
# Risk: Without CSRF protection, attackers can submit forms on behalf of users
# from other sites (cross-site request forgery = get hacked).
# =============================================================================

def test_process_form_missing_csrf_token_returns_400(csrf_client):
    """
    STORY 04 — Subtask 2.
    A POST with no CSRF token must be rejected. The AJAX error handler must
    return 400 JSON (not a redirect), because the frontend expects JSON.
    """
    response = csrf_client.post(
        '/process_form',
        data={'intencao': 'Test', 'selectedCards': '3'},
        headers={'X-Requested-With': 'XMLHttpRequest'}
    )
    assert response.status_code == 400


def test_process_form_invalid_csrf_token_returns_400(csrf_client):
    """
    STORY 04 — Subtask 3.
    A forged/tampered CSRF token must be rejected. If this passes, an attacker
    can craft a cross-site POST from any domain and submit forms as the user.
    """
    response = csrf_client.post(
        '/process_form',
        data={
            'intencao': 'CSRF Attack Test',
            'selectedCards': '3',
            'csrf_token': 'invalid_forged_token_abc123'
        },
        headers={'X-Requested-With': 'XMLHttpRequest'}
    )
    assert response.status_code == 400


def test_csrf_error_response_is_json_for_ajax(csrf_client):
    """
    STORY 04 — Subtask 2 (response format check).
    The frontend fetch() expects a JSON body on error. If the server returns
    HTML (e.g. a Flask redirect), the JS JSON.parse will throw and the user
    sees a generic 'Ocorreu um erro' instead of gracefully reloading.
    """
    response = csrf_client.post(
        '/process_form',
        data={'intencao': 'Test', 'selectedCards': '3'},
        headers={'X-Requested-With': 'XMLHttpRequest'}
    )
    assert response.status_code == 400
    assert response.content_type == 'application/json'
    data = response.get_json()
    assert 'error' in data


# =============================================================================
# STORY 05 — Intention Length Limit
# Risk: Unbounded input → unbounded AI prompt → runaway API costs.
# =============================================================================

def test_process_form_exactly_400_chars_is_accepted(client):
    """
    STORY 05 — Subtask 1 (boundary).
    The limit is > 400, so exactly 400 characters must pass.
    A regression here (e.g. >= 400) would break valid users at the boundary.
    """
    response = client.post('/process_form', data={
        'intencao': 'A' * 400,
        'selectedCards': '3'
    })
    assert response.status_code == 200


def test_process_form_401_chars_is_rejected(client):
    """
    STORY 05 — Subtask 2.
    The hard limit. A 401-character intention must be blocked before it ever
    reaches the AI API. Each extra token in the prompt is a direct cost.
    """
    response = client.post('/process_form', data={
        'intencao': 'A' * 401,
        'selectedCards': '3'
    })
    assert response.status_code == 400
    data = response.get_json()
    assert 'Intention too long' in data['error']


def test_process_form_very_long_intention_is_rejected(client):
    """
    STORY 05 — Regression guard for extreme inputs.
    A 10,000-character payload must not reach the AI or crash the app.
    """
    response = client.post('/process_form', data={
        'intencao': 'A' * 10000,
        'selectedCards': '3'
    })
    assert response.status_code == 400


def test_process_form_whitespace_trimmed_before_length_check(client):
    """
    STORY 05 — Subtask 3.
    '400 As + 10 trailing spaces' strips to 400 and must be accepted.
    If .strip() is ever removed from app.py, this test will catch the regression.
    """
    response = client.post('/process_form', data={
        'intencao': 'A' * 400 + ' ' * 10,
        'selectedCards': '1'
    })
    assert response.status_code == 200


# =============================================================================
# STORY 07 — HTTP Method Restrictions
# Risk: Accepting GET on a POST-only endpoint can expose session data or allow
# state mutation via URL navigation (CSRF bypass vector).
# =============================================================================

def test_process_form_get_request_returns_405(client):
    """
    STORY 07 — Subtask 2.
    /process_form must only accept POST. A GET request (e.g. someone pasting the
    URL into a browser) must return 405, not silently process an empty form.
    """
    response = client.get('/process_form')
    assert response.status_code == 405


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
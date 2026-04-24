import pytest
from app import sanitize_input


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

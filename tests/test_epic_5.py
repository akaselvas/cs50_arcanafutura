# =============================================================================
# test_epic_05.py — Epic 05: Security, Performance & Infrastructure
#
# Place this file in your tests/ folder alongside test_epic_01.py … 04.py.
# It is self-contained: all fixtures are defined here so there is no dependency
# on the other Epic files.
#
# Scope of automation (applied filter: crash / hacked / costs money):
#
#   STORY 01 — Rate Limiting
#     The /results route's @limiter.limit decorator must produce a 429 when
#     exceeded. If the limiter is disabled or crashes into a 500, the AI
#     endpoint is unmetered → unlimited API quota drain.
#     Automated: 2 tests (mechanism + global default limit).
#     Not automated: time-based window reset (requires 61 s sleep),
#     IP isolation (requires 2 IPs), Redis CLI inspection.
#
#   STORY 02 — Cookie Security
#     HttpOnly and SameSite=Lax are the first defences against session
#     hijacking via XSS and CSRF. Secure=False in dev / True in prod must
#     match is_production exactly — a regression in either direction is
#     exploitable or breaks development entirely.
#     Automated: 4 tests.
#     Not automated: manual DevTools inspection, cookie signature decoding.
#
#   STORY 04 — CSP Header Enforcement
#     The Content-Security-Policy header is the browser's primary XSS
#     mitigation. Its absence means the browser will execute any injected
#     script without restriction.
#     Automated: 2 tests (header presence + no wildcard in script-src).
#     Not automated: browser enforcement of blocked resources (Playwright).
#
#   STORY 05 — WebSocket CSRF
#     Flask-Limiter only covers HTTP. WebSocket events bypass it entirely.
#     The validate_csrf() guard in handle_generation and handle_message is
#     the only barrier against Cross-Site WebSocket Hijacking (CSWSH) and
#     against authenticated users making unlimited free AI calls via the
#     chat socket.
#     Automated: 4 tests.
#     Not automated: UI error display, per-user token isolation.
#
#   STORY 06 — Data Isolation
#     If session isolation breaks, User A sees User B's cards and intention
#     (data breach). The same-browser race condition can corrupt the
#     selected_cards value in a shared session, causing /cartas to crash.
#     Automated: 2 tests.
#     Not automated: Redis key inspection, WS room isolation, two-browser
#     tests (all require external tooling or concurrent real browsers).
# =============================================================================

import re
import time
import threading
import pytest

from app import app, limiter, socketio


# =============================================================================
# FIXTURES
# All three fixtures are self-contained. Do not import from other test files.
# =============================================================================

@pytest.fixture
def client():
    """Standard test client with CSRF disabled (functional/logic tests)."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as c:
        yield c
    app.config['WTF_CSRF_ENABLED'] = True


@pytest.fixture
def csrf_client():
    """Test client with CSRF enabled (security tests that need real token flow)."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = True
    with app.test_client() as c:
        yield c
    app.config['WTF_CSRF_ENABLED'] = False


@pytest.fixture
def socket_client(client):
    """Socket.IO test client backed by the same Flask test client."""
    sc = socketio.test_client(app, flask_test_client=client)
    yield sc
    if sc.is_connected():
        sc.disconnect()


# =============================================================================
# HELPER
# =============================================================================

def _setup_results_session(client):
    """
    Drive the client through /process_form so the session has
    intencao, selected_cards, and choosed_cards. Required before any
    request to /results that should not redirect to /cartas.
    """
    client.post('/process_form', data={'intencao': 'Rate limit test', 'selectedCards': '3'})
    with client.session_transaction() as sess:
        sess['choosed_cards'] = [
            {"name": "O Louco",  "value": "normal"},
            {"name": "A Torre",  "value": "invertido"},
            {"name": "O Sol",    "value": "normal"},
        ]


# =============================================================================
# STORY 01 — API Rate Limiting (DoS / Cost Protection)
# =============================================================================

@pytest.mark.slow
def test_results_rate_limit_returns_429_not_500(client):
    """
    STORY 01 — Subtasks 1 & 7 / Risk: COSTS MONEY.

    The @limiter.limit(rate_limit) decorator on /results must return HTTP 429
    when the limit is exceeded — NOT a 500 crash and NOT an unrestricted 200.

    Strategy: make requests until 429 appears within a generous budget.
    The smallest active limit is the global default (100/hour). After
    limiter.reset(), the counter starts at 0, so request 101 hits the
    hourly ceiling. In dev mode the per-route limit is 200/min, which is
    higher, so the hourly default fires first.

    If 429 never appears in 110 requests, the limiter is either disabled,
    not connected to Redis, or the storage backend is silently failing —
    any of which means the AI endpoint is unmetered in production.
    """
    try:
        limiter.reset()
    except Exception:
        pass  # reset() may not be available in all Flask-Limiter versions;
              # test will still work if the counter happens to be at 0.

    _setup_results_session(client)

    hit_429 = False
    for i in range(110):                   # 10 requests over the 100/hr global limit
        r = client.get('/results')
        if r.status_code == 429:
            hit_429 = True
            break
        assert r.status_code in (200, 302), (
            f"Request {i + 1} returned unexpected status {r.status_code}. "
            "The rate limiter should return 200 (OK) or 302 (redirect) until the "
            "limit is exceeded, then 429. A 500 here means the limiter itself is "
            "crashing — likely a misconfigured Redis connection."
        )

    assert hit_429, (
        "Rate limiter never returned 429 after 110 requests to /results. "
        "Possible causes:\n"
        "  1. limiter is disabled (RATELIMIT_ENABLED=False somewhere in config)\n"
        "  2. Storage is not Redis — in-memory storage does not persist across "
        "     workers, silently allowing unlimited requests in multi-process deployments\n"
        "  3. The @limiter.limit(rate_limit) decorator was accidentally removed from "
        "     the /results route\n"
        "Consequence: the Gemini AI endpoint has no quota guard in production."
    )


def test_home_page_global_rate_limit_returns_429(client):
    """
    STORY 01 — Subtask 4 / Risk: COSTS MONEY (indirect).

    The global default_limits=["400 per day", "100 per hour"] applies to
    ALL routes including / (Home). This verifies Flask-Limiter is actually
    active for routes that do NOT have an explicit @limiter.limit decorator.
    If global limits are broken, an attacker can flood /process_form
    indefinitely, creating unlimited sessions and exhausting the Redis pool.

    We test / (the simplest route) to avoid interfering with other tests
    that use /results.
    """
    try:
        limiter.reset()
    except Exception:
        pass

    hit_429 = False
    for i in range(110):                   # global hourly limit is 100
        r = client.get('/')
        if r.status_code == 429:
            hit_429 = True
            break
        assert r.status_code == 200, (
            f"GET / returned {r.status_code} on request {i + 1}. "
            "Expected 200 until the hourly limit is exceeded."
        )

    assert hit_429, (
        "Global rate limit (100 per hour) was never triggered after 110 GET / requests. "
        "Flask-Limiter's default_limits are not being applied — any route without an "
        "explicit @limiter.limit decorator is effectively unprotected."
    )


# =============================================================================
# STORY 02 — Secure Session Cookie Configuration
# =============================================================================

def _get_session_cookie_header(client):
    """
    Request the home page (which always modifies the session via session.pop)
    and return the raw Set-Cookie header string for the 'session' cookie.
    """
    response = client.get('/')
    all_cookies = response.headers.getlist('Set-Cookie')
    session_cookies = [c for c in all_cookies if c.lower().startswith('session=')]
    assert session_cookies, (
        "No 'session' cookie was found in the Set-Cookie response header after GET /. "
        "Check SESSION_COOKIE_NAME='session' in app.config and that SESSION_TYPE='redis' "
        "is correctly initialised. Without a session cookie the whole app is broken."
    )
    return session_cookies[0]


def test_session_cookie_has_httponly_flag(client):
    """
    STORY 02 — Subtask 1 / Risk: GET HACKED.

    SESSION_COOKIE_HTTPONLY=True must produce a Set-Cookie header with the
    HttpOnly attribute. Without it, any XSS payload can steal the session
    token via document.cookie and hijack the user's session server-side.
    """
    cookie = _get_session_cookie_header(client)
    assert 'HttpOnly' in cookie, (
        f"HttpOnly attribute missing from session cookie: '{cookie}'. "
        "An XSS payload on any page can steal this token with document.cookie. "
        "Fix: verify SESSION_COOKIE_HTTPONLY=True in app.config."
    )


def test_session_cookie_has_samesite_lax(client):
    """
    STORY 02 — Subtask 2 / Risk: GET HACKED.

    SESSION_COOKIE_SAMESITE='Lax' must appear in the Set-Cookie header.
    Without SameSite, the browser sends the session cookie on cross-site
    POST requests — the Flask-WTF CSRF token is the backup defence, but
    defence in depth requires BOTH layers. A SameSite=None or absent value
    weakens CSRF protection across all forms.
    """
    cookie = _get_session_cookie_header(client)
    assert 'SameSite=Lax' in cookie, (
        f"SameSite=Lax missing from session cookie: '{cookie}'. "
        "Cross-site POST requests will include the session cookie, "
        "meaning CSRF protection relies solely on the WTF token. "
        "Fix: verify SESSION_COOKIE_SAMESITE='Lax' in app.config."
    )


def test_session_cookie_secure_flag_is_false_in_dev(client):
    """
    STORY 02 — Subtask 3 / Risk: CRASH (breaks all local development).

    In development (RENDER not set), SESSION_COOKIE_SECURE must be False.
    If someone hard-codes True, the browser refuses to send the cookie over
    plain HTTP (http://localhost), breaking every page that reads the session.
    This test guards against that regression.
    """
    from app import is_production
    if is_production:
        pytest.skip("Running in production — Secure=True is correct; skip the dev check.")

    cookie = _get_session_cookie_header(client)
    # The string '; Secure' should NOT appear for dev HTTP sessions.
    assert '; Secure' not in cookie, (
        f"Secure attribute is set in development: '{cookie}'. "
        "This prevents the browser from sending the cookie over plain HTTP "
        "(http://localhost), breaking the entire session flow locally. "
        "Fix: verify SESSION_COOKIE_SECURE=is_production in app.config."
    )


def test_session_cookie_secure_flag_matches_is_production():
    """
    STORY 02 — Subtask 4 / Risk: GET HACKED (in production) or CRASH (in dev).

    The Secure flag must be dynamically tied to is_production, not hardcoded.
    This test is environment-agnostic: it reads the actual app.config value
    and verifies it equals is_production — catching both:
      - is_production=True but Secure=False → session cookie sent over HTTP
        in production, interceptable by a network attacker.
      - is_production=False but Secure=True → cookie refused over HTTP in dev,
        breaking every developer's local session.
    """
    from app import is_production
    actual_secure = app.config.get('SESSION_COOKIE_SECURE')
    assert actual_secure == is_production, (
        f"SESSION_COOKIE_SECURE ({actual_secure}) does not match "
        f"is_production ({is_production}). "
        "The value must be dynamic (SESSION_COOKIE_SECURE=is_production), "
        "not hardcoded. A hardcoded False in production exposes the session "
        "cookie to network eavesdroppers on HTTP."
    )


# =============================================================================
# STORY 04 — Content Security Policy (CSP) Enforcement
# =============================================================================

def test_csp_header_is_present_on_every_response(client):
    """
    STORY 04 — Subtask 1 / Risk: GET HACKED.

    The Content-Security-Policy header must be present on all pages.
    Flask-Talisman injects it via middleware, so its absence on ANY route
    means Talisman has been removed, bypassed, or misconfigured.

    Without CSP, the browser will execute any script injected by XSS,
    load resources from any domain, and send cookies to any destination.
    Every other XSS mitigation (nonces, bleach, HttpOnly) becomes a single
    point of failure without CSP as the outermost ring.
    """
    for route in ['/', '/cartas', '/results']:
        response = client.get(route)
        csp = response.headers.get('Content-Security-Policy')
        assert csp is not None, (
            f"Content-Security-Policy header is missing from '{route}'. "
            "Talisman may have been removed or the route is not going through "
            "the full WSGI middleware stack. Without this header, the browser "
            "has no instruction to block injected scripts or external resources."
        )
        assert len(csp) > 10, (
            f"Content-Security-Policy header on '{route}' is suspiciously short: '{csp}'. "
            "An empty or trivial policy provides no protection."
        )


def test_csp_script_src_does_not_allow_all_origins(client):
    """
    STORY 04 — Subtasks 3 & 7 / Risk: GET HACKED.

    A bare wildcard `*` in script-src completely defeats the policy —
    any external script from any domain can be loaded and executed.
    This test verifies the script-src directive contains specific trusted
    origins (cdnjs.cloudflare.com, 'self') and NOT a permissive wildcard.

    Note: 'unsafe-inline' in script-src is also dangerous when used without
    nonces (it allows inline <script> execution). This test verifies the
    current policy structure is not trivially bypassable.
    """
    response = client.get('/')
    csp = response.headers.get('Content-Security-Policy', '')

    assert 'script-src' in csp, (
        "script-src directive is absent from the CSP header. "
        "When script-src is missing, the browser falls back to default-src, "
        "but an explicit script-src is required to allow the Socket.IO and "
        "marked.js CDN scripts used by the results page."
    )

    # Parse only the script-src segment for precise matching
    directives = {
        d.strip().split()[0]: d.strip()
        for d in csp.split(';') if d.strip()
    }
    script_src = directives.get('script-src', '')

    # A bare * as a source value means "allow scripts from anywhere"
    sources = script_src.replace('script-src', '').split()
    assert '*' not in sources, (
        f"script-src contains a wildcard '*': '{script_src}'. "
        "This defeats the entire script policy — any external script "
        "can be injected and will execute without restriction. "
        "Replace * with explicit trusted origins."
    )
    assert 'cdnjs.cloudflare.com' in script_src, (
        "cdnjs.cloudflare.com is missing from script-src. "
        "Socket.IO and marked.js are loaded from this CDN. "
        "If they are not whitelisted, the results page will be broken "
        "in production (Talisman blocks the scripts)."
    )


# =============================================================================
# STORY 05 — WebSocket CSRF Enforcement
# =============================================================================

def test_start_generation_rejects_missing_csrf_token(socket_client):
    """
    STORY 05 — Subtask 2 / Risk: GET HACKED (Cross-Site WebSocket Hijacking).

    The handle_generation handler's first action is:
        csrf_token = data.get('csrf_token')
        if not csrf_token:
            emit('generation_error', {'message': 'CSRF token missing.'})
            return

    An attacker who has established a WebSocket connection (possible because
    WebSockets bypass the SameSite cookie restriction on some browser
    versions) but has no valid CSRF token must NOT be able to trigger the
    Gemini API. This test verifies the 'generation_error' short-circuit
    fires BEFORE any background_generate task is started.
    """
    socket_client.emit('start_generation', {
        'intencao':       'Attack attempt',
        'selected_cards': '3',
        'choosed_cards':  [{"name": "O Louco", "value": "normal"}]
        # csrf_token key intentionally absent
    })
    received = socket_client.get_received()

    error_events = [r for r in received if r['name'] == 'generation_error']
    assert len(error_events) > 0, (
        "No 'generation_error' event was emitted when csrf_token was absent from "
        "the start_generation payload. The AI generation proceeded without any "
        "CSRF validation — a cross-site attacker can trigger unlimited Gemini API "
        "calls at the application's cost."
    )

    message = error_events[0]['args'][0].get('message', '')
    assert len(message) > 0, (
        "generation_error was emitted but with an empty 'message' field. "
        "The user will see a blank error indicator — they won't know to reload."
    )


def test_start_generation_rejects_invalid_csrf_token(socket_client):
    """
    STORY 05 — Subtask 3 / Risk: GET HACKED.

    A forged or expired CSRF token must fail validate_csrf() and emit
    'generation_error' via the except ValidationError block, preventing
    any AI generation from being triggered.

    This is the Cross-Site WebSocket Hijacking (CSWSH) attack scenario:
    an attacker's page establishes a WS connection via the victim's browser,
    but cannot read the CSRF token from the victim's <meta> tag
    (blocked by Same-Origin Policy). They must use a forged token, which
    must be rejected here.
    """
    socket_client.emit('start_generation', {
        'intencao':       'CSWSH attack',
        'selected_cards': '3',
        'choosed_cards':  [{"name": "A Torre", "value": "invertido"}],
        'csrf_token':     'forged_invalid_token_xyz_cswsh_attempt'
    })
    received = socket_client.get_received()

    error_events = [r for r in received if r['name'] == 'generation_error']
    assert len(error_events) > 0, (
        "No 'generation_error' event was emitted when a forged CSRF token was sent "
        "in the start_generation payload. validate_csrf() did not reject the token, "
        "meaning the AI generation executed without a valid token. "
        "An attacker with a WebSocket connection can trigger unlimited AI calls."
    )


def test_send_message_rejects_missing_csrf_token(socket_client):
    """
    STORY 05 — Subtask 2 (chat variant) / Risk: COSTS MONEY.

    The handle_message handler also requires a CSRF token:
        csrf_token = data.get('csrf_token')
        if not csrf_token:
            emit('generation_error', {'message': '...'})
            return

    If this check is ever removed, the chat WebSocket becomes a free,
    unauthenticated interface to the Gemini API. An attacker can send
    arbitrary prompts by emitting send_message events without authentication,
    consuming API quota at the application's cost.

    Each unmetered chat message calls model.generate_content() → direct cost.
    """
    socket_client.emit('send_message', {
        'message':      'Give me a free AI response',
        'tarot_reading': ''
        # csrf_token intentionally absent
    })
    received = socket_client.get_received()

    # The handler emits 'generation_error' for CSRF failures (not 'receive_message')
    error_events = [r for r in received if r['name'] == 'generation_error']
    assert len(error_events) > 0, (
        "No 'generation_error' event was emitted when csrf_token was absent from "
        "the send_message payload. The chat handler accepted the unauthenticated "
        "message and forwarded it to the Gemini API. "
        "An attacker can exploit this to send unlimited free prompts to the AI model, "
        "draining the application's API quota."
    )


def test_csrf_token_meta_tag_is_rendered_in_results_page(client):
    """
    STORY 05 — Subtask 5 / Risk: CRASH (entire results page broken).

    results.html contains:
        <meta name="csrf-token" content="{{ csrf_token() }}">

    The JavaScript reads this tag to populate the csrf_token field in every
    WebSocket payload (start_generation, send_message). If this tag is
    missing or its content is empty, EVERY generation request will fail
    immediately with 'CSRF token missing.' — the results page will show the
    error state for every single user, for every reading.

    This is not a gradual failure; it is a complete, immediate breakage of
    the core user flow. The reading will NEVER generate without this tag.
    """
    _setup_results_session(client)
    response = client.get('/results')
    assert response.status_code == 200

    html = response.data.decode('utf-8')

    assert 'name="csrf-token"' in html, (
        "<meta name='csrf-token'> tag is missing from the /results page HTML. "
        "The JavaScript in results.html cannot read the CSRF token and will send "
        "'csrf_token: undefined' in every WebSocket payload. "
        "Every single reading will fail with 'CSRF token missing.' on the server."
    )

    # Verify the tag also has a non-empty token value
    match = re.search(r'name=["\']csrf-token["\'].*?content=["\']([^"\']+)["\']', html)
    if not match:
        match = re.search(r'content=["\']([^"\']+)["\'].*?name=["\']csrf-token["\']', html)

    assert match and len(match.group(1)) > 10, (
        "The <meta name='csrf-token'> tag exists but its content is empty or too short. "
        "An empty token will fail validate_csrf() on the server for every generation request. "
        "Verify that {{ csrf_token() }} is being evaluated by Jinja2 and that the "
        "CSRF extension is correctly initialized."
    )


# =============================================================================
# STORY 06 — Data Isolation (Concurrent Users)
# =============================================================================

def test_two_clients_have_isolated_sessions():
    """
    STORY 06 — Subtask 1 / Risk: GET HACKED (cross-user data leakage).

    Each browser gets its own Redis-backed session, keyed by a unique
    cookie. If session isolation breaks (e.g., someone accidentally uses
    a global dict instead of Flask's session object), User A would receive
    User B's intention and card selection — a data breach.

    This test simulates User A and User B submitting different form data
    simultaneously and verifies their sessions remain independent.
    """
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client_a:
        with app.test_client() as client_b:

            client_a.post('/process_form', data={
                'intencao':     'User A — love reading',
                'selectedCards': '3'
            })
            client_b.post('/process_form', data={
                'intencao':     'User B — career reading',
                'selectedCards': '1'
            })

            with client_a.session_transaction() as sess_a:
                assert sess_a.get('intencao') == 'User A — love reading', (
                    "User A's session contains the wrong intention. "
                    "Session data may be leaking between clients."
                )
                assert sess_a.get('selected_cards') == '3'
                assert sess_a.get('intencao') != 'User B — career reading', (
                    "User A's session contains User B's intention — "
                    "cross-user session data leakage confirmed."
                )

            with client_b.session_transaction() as sess_b:
                assert sess_b.get('intencao') == 'User B — career reading'
                assert sess_b.get('selected_cards') == '1'
                assert sess_b.get('intencao') != 'User A — love reading', (
                    "User B's session contains User A's intention — "
                    "cross-user session data leakage confirmed."
                )

    app.config['WTF_CSRF_ENABLED'] = True


def test_concurrent_posts_to_process_form_do_not_corrupt_session():
    """
    STORY 06 — Subtask 7 / Risk: CRASH.

    Two tabs in the same browser share the same session cookie. If both tabs
    call /process_form almost simultaneously (one with '1 card', one with
    '5 cards'), the second Redis write may overwrite the first, so Tab A
    proceeds to /cartas with selectedCardsCount = 5 instead of 1.

    In the /cartas template: `const selectedCardsCount = {{ selected_cards }};`
    A corrupted value (0 or wrong number) silently breaks card selection.
    If selected_cards ends up as None, int(None) raises ValueError → 500.

    This test fires two concurrent POSTs from the same session and verifies
    the final session value is one of the two valid inputs (not None, not 0).
    The exact value depends on which write wins the race — we document it.
    """
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    results = {}

    with app.test_client() as shared_client:

        def post_tab_a():
            shared_client.post('/process_form', data={
                'intencao':     'Tab A',
                'selectedCards': '1'
            })

        def post_tab_b():
            shared_client.post('/process_form', data={
                'intencao':     'Tab B',
                'selectedCards': '5'
            })

        thread_a = threading.Thread(target=post_tab_a)
        thread_b = threading.Thread(target=post_tab_b)
        thread_a.start()
        thread_b.start()
        thread_a.join()
        thread_b.join()

        with shared_client.session_transaction() as sess:
            final_cards = sess.get('selected_cards')
            results['selected_cards'] = final_cards

    # The session must contain a valid card count — NOT None and NOT 0.
    # Either '1' or '5' is acceptable (last-write-wins is expected behaviour).
    # None means the key was lost entirely → int(None) crashes /cartas with 500.
    assert results['selected_cards'] is not None, (
        "session['selected_cards'] is None after concurrent /process_form requests. "
        "int(None) in the /cartas route raises ValueError → HTTP 500 for the user. "
        "The /cartas route now guards against this with: "
        "if raw_val not in ['1','3','5']: return redirect(url_for('home')), "
        "but the session write race condition still causes a broken user experience. "
        "Consider adding a server-side lock or per-tab session isolation."
    )
    assert results['selected_cards'] in ('1', '3', '5'), (
        f"session['selected_cards'] contains an invalid value: "
        f"'{results['selected_cards']}'. Expected '1', '3', or '5'. "
        "A corrupted value would cause the /cartas validation guard to "
        "redirect the user to home, silently losing their game state."
    )

    app.config['WTF_CSRF_ENABLED'] = True
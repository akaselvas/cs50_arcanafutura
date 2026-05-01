# =============================================================================
# test_epic_08.py — Epic 08: Security Headers, CORS, Missing Protections & Dev Leaks
#
# Place this file in your tests/ folder alongside test_epic_01.py … 07.py.
#
# ─────────────────────────────────────────────────────────────────────────────
# IMPORTANT: xfail tests document KNOWN BUGS in the uploaded (current) code.
# They assert the DESIRED SECURE BEHAVIOR, which the tests cannot currently
# achieve. When the developer applies the fix, each xfail becomes xpass —
# the signal to remove the xfail marker and promote it to a regular test.
#
# BUG MAP (uploaded app.py → desired fix):
#
#   BUG 1 (Story 02): cors_allowed_origins="*" is unconditional.
#          Fix: allowed_origins = ["https://arcanafutura.onrender.com"] if is_production else "*"
#          Then: SocketIO(app, cors_allowed_origins=allowed_origins, ...)
#
#   BUG 2 (Story 04): handle_message has no validate_csrf() call.
#          Fix: add csrf_token = data.get('csrf_token') guard before AI call.
#          (Same pattern as handle_generation.)
#
#   BUG 3 (Story 04): handle_message has no in-memory rate limiting.
#          Fix: add is_rate_limited(session_id) check before start_background_task.
#
#   BUG 4 (Story 05): script-src contains 'unsafe-inline' and 'unsafe-eval'.
#          CSP nonce is generated (g.nonce) but Talisman is NOT initialized with
#          content_security_policy_nonce_in=['script-src'].
#          Fix: remove 'unsafe-inline'/'unsafe-eval', add nonce_in to Talisman.
#
# ─────────────────────────────────────────────────────────────────────────────
# NOT AUTOMATED — requires browser or live HTTPS deployment:
#   Story 01 S4,5  — HSTS header (requires HTTPS)
#   Story 02 S1-3  — External cross-origin WS connection (requires real browser)
#   Story 03       — Forced HTTPS redirect / ProxyFix (requires Render)
#   Story 05 S3    — DOM script injection executes (requires browser)
#   Story 06 S1-3  — BrowserSync in rendered HTML (layout.html has it as HTML
#                    comment, not Jinja2 logic — nothing to assert server-side)
#   Story 07       — Real IP rate limiting (requires Render + multiple IPs)
# =============================================================================

import re
import inspect
import pytest
from app import app, handle_message, socketio


# =============================================================================
# FIXTURE
# =============================================================================

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as c:
        yield c
    app.config['WTF_CSRF_ENABLED'] = True


# =============================================================================
# STORY 01 — HTTP Security Headers (Talisman Defaults)
#
# Risk: GET HACKED
#
# Flask-Talisman injects these headers via WSGI middleware. Their absence
# means Talisman has been removed, bypassed, or never initialised, opening
# three distinct attack surfaces simultaneously:
#
#   X-Frame-Options: SAMEORIGIN   → blocks clickjacking iframes
#   X-Content-Type-Options: nosniff → blocks MIME-type confusion attacks
#   Referrer-Policy               → prevents URL path leakage to external sites
#
# These are tested across three response types (200, 302 redirect from 404,
# and real 404 for static files) because Talisman wraps at the WSGI level —
# if it ever stops wrapping error responses, each type fails independently.
# =============================================================================

@pytest.mark.parametrize("route", ['/', '/cartas', '/results'])
def test_x_frame_options_sameorigin_on_all_routes(client, route):
    """
    STORY 01 — Subtask 1 / Risk: GET HACKED (clickjacking).

    X-Frame-Options: SAMEORIGIN prevents the application from being embedded
    in an iframe on a malicious third-party site. Without it, an attacker
    can overlay an invisible iframe over a legitimate page and trick users
    into clicking buttons (card selections, chat sends) they cannot see.

    Tested on all three main routes to confirm Talisman wraps every response,
    not just the home page.
    """
    response = client.get(route)
    xfo = response.headers.get('X-Frame-Options')
    assert xfo is not None, (
        f"X-Frame-Options header missing from '{route}'. "
        "Talisman may have been removed or misconfigured. "
        "Without this header, the app can be embedded in an attacker's iframe."
    )
    assert xfo.upper() == 'SAMEORIGIN', (
        f"X-Frame-Options is '{xfo}' on '{route}', expected 'SAMEORIGIN'. "
        "DENY would also be acceptable, but SAMEORIGIN is Talisman's default. "
        "A value of ALLOWALL removes all clickjacking protection."
    )


def test_x_content_type_options_nosniff_present(client):
    """
    STORY 01 — Subtask 2 / Risk: GET HACKED (MIME sniffing).

    X-Content-Type-Options: nosniff prevents browsers from guessing a
    file's content type. Without it, an attacker who can upload a file
    (or inject content) could serve a JavaScript payload disguised as
    an image — the browser might execute it instead of displaying it.
    """
    response = client.get('/')
    nosniff = response.headers.get('X-Content-Type-Options')
    assert nosniff is not None, (
        "X-Content-Type-Options header is missing. "
        "Without nosniff, browsers may MIME-sniff uploaded or reflected content "
        "and execute it as JavaScript even if the Content-Type says otherwise."
    )
    assert nosniff.lower() == 'nosniff', (
        f"X-Content-Type-Options is '{nosniff}', expected 'nosniff'. "
        "Any value other than 'nosniff' provides no MIME protection."
    )


def test_referrer_policy_header_present(client):
    """
    STORY 01 — Subtask 3 / Risk: GET HACKED (URL path leakage).

    The Referrer-Policy header controls how much of the current URL is
    sent in the Referer header when a user navigates to an external link.
    Without it, visiting an external link from /results?session=... would
    expose the full URL path to the destination server's access logs.

    Talisman's default is 'strict-origin-when-cross-origin': full URL for
    same-origin requests, only the origin for cross-origin.
    """
    response = client.get('/')
    referrer = response.headers.get('Referrer-Policy')
    assert referrer is not None, (
        "Referrer-Policy header is missing. "
        "Without it, navigation to external links exposes the full URL "
        "(including any session-related path segments) to third-party servers."
    )
    assert len(referrer) > 0, "Referrer-Policy header is present but empty."


def test_talisman_security_headers_present_on_404_redirect(client):
    """
    STORY 01 — Subtask 6 / Risk: GET HACKED.

    The custom 404 handler returns a 302 redirect. This 302 response must
    still carry all Talisman security headers. If Talisman's WSGI wrapper
    ever stops wrapping non-200 responses, an attacker who controls a 404
    trigger (e.g., via open redirect or reflected URL) can serve content
    without any X-Frame-Options, making those error-response pages
    embeddable in clickjacking iframes.
    """
    response = client.get('/this-route-does-not-exist-epic08-test')
    # The 404 handler redirects — check headers on that redirect
    assert response.status_code == 302, "Precondition: custom 404 handler must redirect"

    xfo = response.headers.get('X-Frame-Options')
    nosniff = response.headers.get('X-Content-Type-Options')

    assert xfo is not None, (
        "X-Frame-Options missing from the 404 redirect response. "
        "Talisman must wrap ALL responses including redirects triggered by "
        "the custom error handler."
    )
    assert nosniff is not None, (
        "X-Content-Type-Options missing from the 404 redirect response. "
        "Error responses are a common XSS vector if security headers are dropped."
    )


def test_talisman_security_headers_present_on_static_404(client):
    """
    STORY 01 — Subtask 6 (static variant) / Risk: GET HACKED.

    The 404 handler passes static file requests through as real 404s
    (not redirects). This is a different code path. Both code paths must
    be wrapped by Talisman's middleware.
    """
    response = client.get('/static/img/file_that_does_not_exist_epic08.jpg')
    assert response.status_code == 404, "Precondition: static 404 pass-through must return 404"

    xfo = response.headers.get('X-Frame-Options')
    nosniff = response.headers.get('X-Content-Type-Options')

    assert xfo is not None, (
        "X-Frame-Options missing from static file 404 response. "
        "Talisman middleware must wrap the pass-through exception response, "
        "not just redirect responses."
    )
    assert nosniff is not None, (
        "X-Content-Type-Options missing from static file 404 response."
    )


# =============================================================================
# STORY 02 — WebSocket CORS Wildcard Attack Surface
#
# Risk: COSTS MONEY
#
# cors_allowed_origins="*" is unconditional in the uploaded app.py.
# Any external website can establish a WebSocket connection to the server.
# Combined with an unprotected send_message event, this is a free AI
# API proxy for any attacker who knows the server URL.
#
# The test is marked xfail because it asserts the DESIRED secure state
# (cors_allowed_origins is conditional on is_production). The uploaded code
# fails this assertion. The updated user-pasted code passes it.
# =============================================================================

@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN BUG (Story 02 / COSTS MONEY): "
        "cors_allowed_origins is unconditionally '*' in the current app.py. "
        "Any external website can establish a WebSocket connection and, combined "
        "with the unprotected send_message event, use the application as a free "
        "Gemini API proxy. "
        "Fix: allowed_origins = ['https://arcanafutura.onrender.com'] if is_production else '*' "
        "then: SocketIO(app, cors_allowed_origins=allowed_origins, ...). "
        "Remove xfail once the conditional is applied."
    )
)
def test_cors_allowed_origins_is_conditional_not_unconditional_wildcard():
    """
    STORY 02 — Subtask 4 (source inspection) / Risk: COSTS MONEY.

    Inspects app.py source to confirm that `cors_allowed_origins` is set
    conditionally (restricted to the production domain in production, `*`
    only in development), not hardcoded as `*` for all environments.

    An unconditional `*` means ANY website can:
    1. Open a WebSocket connection to the server
    2. (If send_message lacks CSRF) Emit chat messages that cost API quota
    3. Scrape socket events without the browser's Same-Origin Policy protection

    This test currently FAILS (xfail) because the uploaded code uses `"*"`
    unconditionally. It will pass when the fix is applied.
    """
    import app as app_module
    source = inspect.getsource(app_module)

    # The secure pattern: cors_allowed_origins is a variable, not a literal
    # The conditional must reference is_production before the SocketIO() call
    has_conditional_cors = (
        'cors_allowed_origins' in source
        and 'is_production' in source
        and 'allowed_origins' in source
    )
    assert has_conditional_cors, (
        "cors_allowed_origins='*' is still hardcoded unconditionally. "
        "In production, this allows any external website to connect to the "
        "WebSocket server. Replace with a conditional: "
        "allowed_origins = ['https://arcanafutura.onrender.com'] if is_production else '*'"
    )

    # Verify the production value is the specific domain, not '*'
    assert '"*"' not in source.split('cors_allowed_origins=')[1].split('\n')[0], (
        "cors_allowed_origins is still set to '*' on the SocketIO() line. "
        "After the fix, SocketIO should receive the variable `allowed_origins`, "
        "not the literal string '*'."
    )


# =============================================================================
# STORY 04 — send_message WebSocket Event Has No CSRF Protection
#
# Risk: COSTS MONEY
#
# handle_generation() calls validate_csrf() — protected.
# handle_message() in the uploaded code does NOT — unprotected.
#
# An authenticated WebSocket connection (even from an external origin, since
# CORS is wildcard) can send unlimited chat messages directly to Gemini
# without any CSRF token. Each message is a real API call.
#
# Note: Epic 04's xfail tests already cover this. These tests are from the
# perspective of Epic 08's explicit documentation requirement — they provide
# the formal security-test evidence that the fix is in place.
# =============================================================================

@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN BUG (Story 04 / COSTS MONEY): "
        "handle_message lacks validate_csrf(). Any authenticated WebSocket "
        "client can call send_message without a CSRF token, forwarding "
        "arbitrary prompts to the Gemini API at the application's cost. "
        "Fix: add csrf_token = data.get('csrf_token') guard, matching "
        "the pattern in handle_generation(). "
        "Remove xfail once validate_csrf is added to handle_message."
    )
)
def test_handle_message_has_csrf_validation():
    """
    STORY 04 — Subtask 1 / Risk: COSTS MONEY.

    Inspects handle_message source to confirm validate_csrf() is called
    before any AI processing begins. Without it, the chat endpoint is a
    free, unauthenticated Gemini API proxy for any connected WebSocket client.
    """
    source = inspect.getsource(handle_message)
    assert 'validate_csrf' in source, (
        "validate_csrf() is not called in handle_message. "
        "Any WebSocket client can send chat messages without a CSRF token, "
        "calling model.generate_content() and consuming API quota freely. "
        "Add: csrf_token = data.get('csrf_token') followed by validate_csrf(csrf_token)."
    )
    assert "data.get('csrf_token')" in source or 'data.get("csrf_token")' in source, (
        "handle_message does not extract a csrf_token from the event payload. "
        "Even if validate_csrf is present, it needs the token to validate."
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN BUG (Story 04 / COSTS MONEY): "
        "handle_message has no in-memory rate limiting. Flask-Limiter's "
        "@limiter.limit decorator only protects HTTP routes, not SocketIO "
        "events. An attacker can send unlimited chat messages via WebSocket, "
        "bypassing the HTTP rate limiter entirely. "
        "Fix: add is_rate_limited(session_id) check before background_chat. "
        "Remove xfail once the in-memory limiter is wired into handle_message."
    )
)
def test_handle_message_calls_in_memory_rate_limiter():
    """
    STORY 04 — Subtask 3 / Risk: COSTS MONEY.

    Flask-Limiter applies only to HTTP routes via @limiter.limit. WebSocket
    events are invisible to it. Without a separate in-memory rate limiter in
    handle_message, an attacker can emit 1,000 send_message events per second
    — each triggering a Gemini API call — while the HTTP rate limiter watches
    a completely different code path.

    The fix (in the updated code) adds an is_rate_limited() function and calls
    it at the top of handle_message before any AI processing.
    """
    source = inspect.getsource(handle_message)
    assert 'is_rate_limited' in source, (
        "handle_message does not call is_rate_limited(). "
        "Flask-Limiter (@limiter.limit) does NOT protect SocketIO events — "
        "it only applies to HTTP routes decorated with @app.route. "
        "Without an in-memory rate check here, an attacker can emit unlimited "
        "send_message events, each consuming Gemini API quota."
    )


def test_in_memory_rate_limiter_function_exists_in_app():
    """
    STORY 04 — Subtask 3 (companion) / Risk: COSTS MONEY.

    Verifies the is_rate_limited function exists in app.py and uses a
    sliding-window algorithm (time-based expiry), not a fixed counter that
    resets on server restart. A fixed counter can be gamed by waiting for
    the deployment cycle.

    This test passes even against the UPLOADED code because the function
    exists — it just isn't called from handle_message (that's the xfail above).
    When both tests pass, the rate limiter is both defined AND wired in.
    """
    import app as app_module
    assert hasattr(app_module, 'is_rate_limited'), (
        "is_rate_limited function not found in app.py. "
        "Flask-Limiter cannot protect SocketIO events. A custom in-memory "
        "sliding-window limiter must be defined and called from handle_message."
    )

    source = inspect.getsource(app_module.is_rate_limited)

    # Sliding window requires time-based expiry, not just a counter
    assert 'time' in source.lower() or 'timestamp' in source.lower(), (
        "is_rate_limited does not use time-based expiry. A static counter "
        "can be bypassed by simply reconnecting the WebSocket."
    )
    assert 'return True' in source, (
        "is_rate_limited never returns True — it never actually blocks anyone. "
        "The function must return True when the limit is exceeded."
    )


# =============================================================================
# STORY 05 — g.nonce Generated But CSP Does Not Enforce It
#
# Risk: GET HACKED (XSS)
#
# The uploaded code has a fundamental misconfiguration:
#   - g.nonce = secrets.token_hex(16) is generated on every request ✓
#   - Templates apply nonce="{{ g.nonce }}" to inline script tags ✓
#   - BUT: Talisman(app, content_security_policy=csp) has NO nonce_in parameter ✗
#   - AND: csp['script-src'] contains "'unsafe-inline'" ✗
#
# The result: the browser sees nonce="abc123" on the script tag but IGNORES it
# because 'unsafe-inline' already allows ALL inline scripts unconditionally.
# The nonce decoration is cosmetically present but provides zero security.
# Any script injected via XSS executes freely because 'unsafe-inline' overrides
# the nonce restriction entirely.
#
# The fix (in the updated code):
#   1. Remove 'unsafe-inline' from csp['script-src']
#   2. Talisman(app, ..., content_security_policy_nonce_in=['script-src'])
#   3. Templates use {{ csp_nonce() }} instead of {{ g.nonce }}
# =============================================================================

@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN BUG (Story 05 / GET HACKED): "
        "'unsafe-inline' is present in script-src. This completely overrides "
        "the nonce mechanism — the browser allows ALL inline scripts when "
        "unsafe-inline is present, regardless of whether they have a valid nonce. "
        "XSS via any injection point (AI output, reflected URL, etc.) executes "
        "without restriction. "
        "Fix: remove \"'unsafe-inline'\" from csp['script-src'] and add "
        "content_security_policy_nonce_in=['script-src'] to Talisman(). "
        "Remove xfail once unsafe-inline is removed from production script-src."
    )
)
def test_script_src_does_not_contain_unsafe_inline(client):
    """
    STORY 05 — Subtask 2 / Risk: GET HACKED.

    The Content-Security-Policy header's script-src directive must NOT
    contain 'unsafe-inline' in any environment. When unsafe-inline is
    present, the nonce attribute on script tags is ignored by the browser.
    Any injected inline script — from XSS in AI output, reflected parameters,
    or DOM injection — executes without restriction.

    This test currently FAILS (xfail) because the uploaded csp dict
    hardcodes "'unsafe-inline'" in script-src. It will pass when removed.
    """
    response = client.get('/')
    csp_header = response.headers.get('Content-Security-Policy', '')
    assert csp_header, "Content-Security-Policy header is missing entirely."

    # Parse only the script-src segment
    directives = {
        d.strip().split()[0]: d.strip()
        for d in csp_header.split(';') if d.strip()
    }
    script_src = directives.get('script-src', '')

    assert "'unsafe-inline'" not in script_src, (
        f"'unsafe-inline' found in script-src: '{script_src}'. "
        "This makes the nonce mechanism completely ineffective. "
        "Any injected script executes because unsafe-inline overrides nonce requirements. "
        "Remove 'unsafe-inline' and add content_security_policy_nonce_in=['script-src'] "
        "to the Talisman() call in app.py."
    )
    assert "'unsafe-eval'" not in script_src, (
        f"'unsafe-eval' found in script-src: '{script_src}'. "
        "unsafe-eval allows eval() and Function() — common XSS escalation vectors. "
        "Remove it unless a specific dependency requires it (and document why)."
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN BUG (Story 05 / GET HACKED): "
        "Talisman is initialized without content_security_policy_nonce_in. "
        "The nonce attribute is applied to script tags in templates, but the "
        "CSP header never contains the matching 'nonce-<value>' source, so the "
        "browser's nonce enforcement is never activated. "
        "Fix: Talisman(app, content_security_policy=csp, "
        "content_security_policy_nonce_in=['script-src']). "
        "Remove xfail once nonce_in is added to the Talisman call."
    )
)
def test_talisman_initialized_with_content_security_policy_nonce_in():
    """
    STORY 05 — Subtask 2 (source inspection variant) / Risk: GET HACKED.

    Even after removing 'unsafe-inline', the nonce mechanism is inert unless
    Talisman is told to inject the per-request nonce value into the CSP header
    via content_security_policy_nonce_in=['script-src']. Without this,
    the CSP header lacks the 'nonce-<value>' source expression, so the browser
    applies no nonce validation — all inline scripts are blocked (if unsafe-inline
    is gone) or all are allowed (if unsafe-inline is still present). Neither
    achieves the intended "allow only nonce-bearing scripts" policy.
    """
    import app as app_module
    source = inspect.getsource(app_module)

    # Find the Talisman() call and check it includes nonce_in
    talisman_call_match = re.search(
        r'Talisman\s*\(.*?\)', source, re.DOTALL
    )
    assert talisman_call_match, "Could not locate Talisman() initialization call in app.py."

    talisman_call = talisman_call_match.group(0)
    assert 'content_security_policy_nonce_in' in talisman_call, (
        f"Talisman() is called without content_security_policy_nonce_in: '{talisman_call}'. "
        "Without this parameter, Talisman does not inject the per-request nonce into "
        "the CSP header. Templates use nonce='...' but the browser sees no matching "
        "'nonce-<value>' in the CSP → nonce enforcement is never activated. "
        "Add: content_security_policy_nonce_in=['script-src']"
    )


def test_nonce_attribute_is_rendered_on_inline_script_tags(client):
    """
    STORY 05 — Subtask 1 / Risk: CRASH (after fix is applied).

    After the nonce fix is applied (unsafe-inline removed, nonce_in added),
    the browser will BLOCK any inline script that does NOT carry a valid nonce.
    This test verifies that inline script tags in the rendered HTML actually
    receive a nonce attribute, so they are not blocked after the fix.

    This test passes against BOTH the old code (g.nonce set by before_request,
    templates use nonce="{{ g.nonce }}") AND the new code (csp_nonce() helper).

    If this test ever FAILS, it means inline script tags have lost their nonce
    attribute — after removing unsafe-inline, the entire application's JS
    would be blocked by the browser, making every page non-functional.
    """
    response = client.get('/')
    assert response.status_code == 200
    html = response.data.decode('utf-8')

    assert 'nonce="' in html, (
        "No nonce attribute found on any inline <script> tag in the home page HTML. "
        "Once 'unsafe-inline' is removed from the CSP, the browser will block ALL "
        "inline scripts that lack a valid nonce. This would make the home page "
        "completely non-functional (JS silent failure, no card selection, no form submit). "
        "Ensure before_request sets g.nonce and templates use nonce='{{ csp_nonce() }}'."
    )

    # Verify the nonce value is a non-trivial string (not empty, not 'None')
    nonce_match = re.search(r'nonce="([^"]+)"', html)
    assert nonce_match, "nonce attribute found but could not extract value."
    nonce_value = nonce_match.group(1)
    assert len(nonce_value) >= 16, (
        f"Nonce value is too short ('{nonce_value}'). "
        "secrets.token_hex(16) produces a 32-character hex string. "
        "A short nonce is brute-forceable."
    )
    assert nonce_value != 'None', (
        "Nonce value is the string 'None' — g.nonce was not set before the template rendered. "
        "Verify before_request() runs and sets g.nonce = secrets.token_hex(16)."
    )


def test_results_page_inline_script_has_nonce_attribute(client):
    """
    STORY 05 — Subtask 5 (regression guard) / Risk: CRASH.

    results.html contains the largest inline script block in the entire app:
    WebSocket initialization, chat handlers, generation events, scroll logic.
    If the nonce attribute is missing from this script tag after the CSP fix
    is applied (unsafe-inline removed), the browser blocks the entire script.
    The result: the reading never generates, the chat never opens, and the
    user sees a frozen loading screen with no error message.

    This is a silent, catastrophic failure — the page loads with HTTP 200,
    but all JavaScript is dead. No console error is shown to the user.
    """
    with client.session_transaction() as sess:
        sess['selected_cards'] = '3'
        sess['intencao'] = 'nonce regression test'
        sess['choosed_cards'] = [
            {"name": "O Louco",  "value": "normal"},
            {"name": "A Torre",  "value": "invertido"},
            {"name": "O Sol",    "value": "normal"},
        ]

    response = client.get('/results')
    assert response.status_code == 200
    html = response.data.decode('utf-8')

    # results.html has one primary inline script block — find all nonces
    nonce_matches = re.findall(r'<script[^>]+nonce="([^"]+)"', html)
    assert len(nonce_matches) > 0, (
        "No inline <script nonce='...'> found on the /results page. "
        "After removing 'unsafe-inline' from the CSP, the browser will block "
        "ALL inline scripts without a valid nonce. The entire results page "
        "(WebSocket connection, AI generation, chat) depends on one large inline "
        "script block. If it lacks a nonce, every user's reading silently fails. "
        "Add nonce='{{ csp_nonce() }}' to the <script> tag in results.html."
    )


# =============================================================================
# STORY 06 — Development URLs Must Not Appear in Production CSP
#
# Risk: GET HACKED (minor, but defence-in-depth violation)
#
# The csp dict adds localhost and LAN IP URLs only when `not is_production`.
# This guard must remain in place. If it's removed or the condition is
# inverted, the production CSP whitelist would include:
#   http://localhost:3000
#   http://192.168.0.102:3000
#   ws://localhost:5000
#   ... etc.
#
# A CSP that whitelists localhost in production is exploitable in some
# attack chains: if an attacker can run code on the server's loopback
# interface (e.g., via SSRF), they can serve a malicious script from
# localhost:3000 and the browser will execute it — the CSP says it's trusted.
#
# More commonly, localhost URLs in a production CSP are a code smell that
# signals the developer may have disabled other security controls.
# =============================================================================

def test_localhost_urls_are_wrapped_in_not_is_production_guard():
    """
    STORY 06 — Subtask 4 / Risk: GET HACKED.

    Inspects app.py source to confirm that all localhost and LAN IP
    entries in the CSP dict are inside `if not is_production:` block.

    This test validates the GUARD EXISTS, not the runtime behaviour.
    Runtime behaviour depends on the RENDER environment variable which
    is not set in CI. Source inspection is the correct approach here
    because it catches the guard being accidentally deleted or inverted
    during a refactor — before the code ever reaches production.
    """
    import app as app_module
    source = inspect.getsource(app_module)

    # Find the block that adds localhost to the CSP
    localhost_section = re.search(
        r'if not is_production.*?localhost.*?(?=\n\n|\Z)',
        source, re.DOTALL
    )
    assert localhost_section is not None, (
        "Could not find 'if not is_production:' block containing localhost CSP entries. "
        "The localhost and LAN IP entries in the CSP must be gated behind this condition. "
        "If the guard is missing, localhost:3000 appears in the production CSP — "
        "in some SSRF + CSP bypass chains, this allows an attacker to serve "
        "scripts from the server's own loopback interface."
    )

    # Verify 'localhost' actually appears inside that conditional block
    matched_block = localhost_section.group(0)
    assert 'localhost' in matched_block, (
        "Found 'if not is_production:' block but localhost is not inside it. "
        "The localhost CSP entry may have been accidentally moved outside the guard."
    )

    # The guard must NOT also add localhost when is_production=True
    # Check the opposite condition isn't present
    bad_pattern = re.search(r'if is_production.*?localhost', source, re.DOTALL)
    assert bad_pattern is None, (
        "Found 'if is_production:' block that adds localhost to the CSP. "
        "This would put localhost URLs in the production CSP — the exact opposite "
        "of the intended behaviour."
    )
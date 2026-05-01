# =============================================================================
# test_epic_07.py — Epic 07: Navigation, Session Guards & Error Handling
#
# Place this file in your tests/ folder alongside test_epic_01.py … 06.py.
#
# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT: WHY THESE TESTS MATTER MORE THAN THEY LOOK
# ─────────────────────────────────────────────────────────────────────────────
#
# The original /cartas route had a known bug:
#
#   Old code (before fix):
#     selected_cards = int(session.get('selected_cards', 0))
#     # No guard → if session is empty, selected_cards = 0
#     # Page renders → selectedCardsCount = 0 in JS
#     # clickedCards >= 0 is immediately true → NO card can be clicked
#     # User is stuck on a visually complete but completely broken page
#     # HTTP status: 200 (success!) — no error visible anywhere
#
#   Updated code (fix applied):
#     raw_val = session.get('selected_cards')
#     if raw_val not in ['1', '3', '5']:
#         return redirect(url_for('home'))
#
# The tests in Story 01 are REGRESSION GUARDS for this fix. If a refactor
# ever reverts to the old pattern (e.g., `session.get('selected_cards', 0)`),
# these tests will immediately turn red.
#
# ─────────────────────────────────────────────────────────────────────────────
# FILTER APPLIED: crash / hacked / costs money
# ─────────────────────────────────────────────────────────────────────────────
#
# NOT AUTOMATED (all require a live browser or infrastructure):
#   Story 02 — Browser back/bfcache DOM state        → Playwright
#   Story 03 — Page refresh JS/WS behavior           → Playwright / duplicates
#   Story 05 — 500 behavior (requires deliberate crash) → Manual
#   Story 06 — Redis failure (requires stopping Redis)  → Manual / integration
#   Story 07 S2,3,4 — Browser close, tab behavior, Redis TTL → Manual
# =============================================================================

import pytest
from app import app


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def client():
    """CSRF disabled — these tests cover routing guards, not token validation."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as c:
        yield c
    app.config['WTF_CSRF_ENABLED'] = True


# =============================================================================
# STORY 01 — Direct URL Navigation (Session Guards)
# =============================================================================

def test_cartas_without_any_session_redirects_to_home(client):
    """
    STORY 01 — Subtask 1 / Risk: CRASH (silent, worst kind).

    This is the regression guard for the most deceptive bug in the app:
    the original /cartas route served HTTP 200 with a fully rendered page
    even when there was no session, because:
        selected_cards = int(session.get('selected_cards', 0))  # → 0
    With selectedCardsCount = 0, the JS condition `clickedCards >= 0` is
    immediately true on page load, so NO card can ever be clicked. The user
    sees 22 beautiful cards and taps them repeatedly — nothing happens. No
    error. No redirect. Just a permanently broken UI.

    The fix (`if raw_val not in ['1', '3', '5']: redirect`) must remain in
    place. This test will fail the instant someone reverts to the old pattern.
    """
    response = client.get('/cartas')

    assert response.status_code == 302, (
        f"/cartas returned {response.status_code} instead of 302 for a session-less request. "
        "The old code returned 200 with a broken page (selectedCardsCount = 0). "
        "The fix must redirect to home. If this fails, the guard was removed or "
        "changed back to: session.get('selected_cards', 0)."
    )
    assert 'home' in response.location or response.location == '/', (
        f"Redirect target is '{response.location}' instead of home ('/'). "
        "A session-less /cartas request must redirect to home so the user "
        "can fill in the form and get a valid session."
    )


@pytest.mark.parametrize("bad_value", [
    '0',      # Numerically valid int, not in ['1','3','5']
    '7',      # Out-of-range number
    '2',      # In-between number not offered by UI
    'abc',    # Non-numeric string
    'null',   # Stringified null (JS-style)
    'None',   # Python None as string
    '',       # Empty string
    '1 OR 1', # SQL-injection-style attempt
])
def test_cartas_with_invalid_session_values_redirects_to_home(client, bad_value):
    """
    STORY 01 — Subtask 2 / Risk: CRASH (selectedCardsCount = 0 or ValueError).

    Tests every plausible corrupt session value against the guard:
        if raw_val not in ['1', '3', '5']: return redirect(url_for('home'))

    Why parametrize? The old `int(session.get('selected_cards', 0))` had
    different failure modes for different inputs:
      - '0'   → int('0') = 0 → page renders broken (no error)
      - 'abc' → int('abc') raises ValueError → caught by try/except, redirects
      - '7'   → int('7') = 7 → page renders, selectedCardsCount = 7 → user
                 MUST click 7 cards but only 22 exist and the stage transition
                 logic breaks waiting for a count that was never valid

    The new string-comparison guard handles all of these identically.
    Any regression to the old int() pattern will cause at least '0' and '7'
    to slip through as a broken 200 response.
    """
    with client.session_transaction() as sess:
        sess['selected_cards'] = bad_value

    response = client.get('/cartas')

    assert response.status_code == 302, (
        f"GET /cartas with session['selected_cards'] = '{bad_value}' "
        f"returned {response.status_code} instead of 302. "
        "The guard `if raw_val not in ['1', '3', '5']` must redirect for all "
        "invalid values. A 200 here means a corrupt session produces a broken page."
    )


def test_cartas_with_valid_session_returns_200_not_over_redirected(client):
    """
    STORY 01 / STORY 03 — Subtask 6 / Risk: CRASH (entire flow broken).

    Regression guard for the OPPOSITE problem: an overly aggressive guard
    that redirects even when the session IS valid. If `raw_val not in
    ['1', '3', '5']` is accidentally changed to `raw_val not in ['1','3','5']
    or True` (a typo, a logic inversion, a wrong default), every user gets
    redirected to home the moment they reach /cartas — the entire flow breaks.

    This test verifies the happy path survives alongside the guard tests above.
    A CI pipeline that only has the "no session → redirect" test would miss a
    regression that makes /cartas redirect unconditionally.
    """
    client.post('/process_form', data={'intencao': 'test', 'selectedCards': '3'})
    response = client.get('/cartas')

    assert response.status_code == 200, (
        f"GET /cartas with a valid session returned {response.status_code} instead of 200. "
        "The redirect guard is over-firing — it is redirecting valid sessions. "
        "The entire user flow is broken: no one can reach the card selection page."
    )
    assert b'data-name=' in response.data, (
        "GET /cartas returned 200 but no card elements were found in the HTML. "
        "The 22-card deck was not rendered. Check the template rendering."
    )


def test_results_get_without_session_redirects_to_cartas(client):
    """
    STORY 01 — Subtask 3 / Risk: CRASH.

    The /results GET branch:
        choosed_cards = session.get('choosed_cards')   # → None
        if not choosed_cards: return redirect(url_for('cartas'))

    If this guard is removed, render_template('results.html', ...,
    choosed_cards=None) is called. The results template iterates over
    choosed_cards in a Jinja2 loop. `for card in None` raises TypeError
    → unhandled 500 for every user who navigates directly to /results.
    """
    response = client.get('/results')

    assert response.status_code == 302, (
        f"GET /results with no session returned {response.status_code} instead of 302. "
        "If the `if not choosed_cards` guard is removed, the Jinja2 template "
        "iterates over None and raises TypeError → 500 for every direct /results visit."
    )
    assert 'cartas' in response.location, (
        f"Redirect target is '{response.location}' — expected /cartas. "
        "A session-less /results must send the user back to card selection, "
        "not to home (where they'd lose their selected card count too)."
    )


def test_results_get_with_partial_session_redirects_to_cartas(client):
    """
    STORY 01 — Subtask 4 / Risk: CRASH.

    A user who completes the Home page form (writing intencao and
    selected_cards to the session) but then manually types /results into
    the URL bar — skipping the card selection step entirely.

    In this state, session['choosed_cards'] does not exist. The guard:
        if not choosed_cards: return redirect(url_for('cartas'))
    must fire even though OTHER session keys are present.

    If the guard is changed to check for session existence rather than
    choosed_cards specifically (e.g., `if not session`), a partial session
    would bypass it and pass None to the template → crash.
    """
    client.post('/process_form', data={'intencao': 'Partial session test', 'selectedCards': '3'})
    # At this point, session has 'intencao' and 'selected_cards' but NOT 'choosed_cards'

    response = client.get('/results')

    assert response.status_code == 302, (
        f"GET /results with a partial session (intencao + selected_cards, no choosed_cards) "
        f"returned {response.status_code} instead of 302. "
        "The guard must check specifically for choosed_cards, not for any session key. "
        "If choosed_cards is None, render_template crashes with TypeError in the Jinja2 loop."
    )
    assert 'cartas' in response.location, (
        f"Expected redirect to /cartas but got '{response.location}'. "
        "The user still has a valid card count in session — they should be sent "
        "back to card selection, not all the way to home."
    )


# =============================================================================
# STORY 04 — HTTP 404 Handler Behavior
# =============================================================================

def test_nonexistent_route_redirects_to_home_not_raw_404(client):
    """
    STORY 04 — Subtask 1 / Risk: GET HACKED (information disclosure).

    The updated app.py has a custom 404 handler:
        @app.errorhandler(404)
        def page_not_found(e):
            if request.path.startswith('/static/') or request.path.endswith('.ico'):
                return e
            return redirect(url_for('home'))

    Without this handler, Flask's default 404 page exposes:
      - The exact Werkzeug version number ("Werkzeug/2.x.x")
      - The Python version
      - The development server warning

    Attackers use version numbers to look up known CVEs. A custom handler
    that redirects to home leaks nothing. This test guards that handler.

    If this returns 404 instead of 302, the custom handler was removed —
    restore @app.errorhandler(404) in app.py.
    """
    response = client.get('/this-route-absolutely-does-not-exist-epic07')

    assert response.status_code == 302, (
        f"GET /nonexistent returned {response.status_code} instead of 302. "
        "The custom 404 handler is missing or not registered. "
        "Flask's default 404 page exposes the Werkzeug version string, "
        "which attackers use to identify exploitable CVEs. "
        "Restore: @app.errorhandler(404) with redirect to url_for('home')."
    )
    assert response.location == '/' or 'home' in response.location, (
        f"Expected redirect to '/' but got '{response.location}'. "
        "The 404 handler must redirect to the home page."
    )


def test_missing_static_file_returns_actual_404_not_redirect(client):
    """
    STORY 04 — Subtask 2 / Risk: GET HACKED (path traversal detection evasion).

    The 404 handler explicitly passes static file requests through:
        if request.path.startswith('/static/') or request.path.endswith('.ico'):
            return e   # ← returns the real 404

    This is correct and intentional. Static files must return 404 — NOT a
    redirect to home — for two reasons:

    1. Security scanning: If missing images always redirect to a 200 page,
       tools like Burp Suite or Nikto cannot determine which static assets
       exist, slightly obscuring the attack surface.

    2. Browser behavior: If <img src="/static/missing.jpg"> gets a 200 HTML
       page as its response, the browser renders the home page HTML as a
       broken image. This causes layout corruption across every page that
       references a missing static asset.

    This test verifies the pass-through logic stays in the handler.
    """
    response = client.get('/static/img/this_image_definitely_does_not_exist_epic07.jpg')

    assert response.status_code == 404, (
        f"GET /static/[missing].jpg returned {response.status_code} instead of 404. "
        "The 404 handler's static file pass-through is broken. "
        "If missing static files redirect to home (302 → 200), browsers will render "
        "the home page HTML as a broken image placeholder — corrupting every "
        "page layout that references a missing asset. "
        "The handler must contain: "
        "if request.path.startswith('/static/'): return e"
    )


def test_csp_header_present_on_nonexistent_route_response(client):
    """
    STORY 04 — Subtask 3 / Risk: GET HACKED.

    Flask-Talisman injects the Content-Security-Policy header via WSGI
    middleware, which wraps every response including redirects and error
    pages. If Talisman is ever misconfigured to skip non-200 responses,
    the redirect from the 404 handler would be sent WITHOUT a CSP header.

    A 302 redirect without CSP is itself low-risk (it has no body), but
    the 302 destination (/) must have CSP — and the presence of CSP on
    ALL responses confirms Talisman is active in the middleware stack.

    If this fails, check that Talisman is still initialized as:
        Talisman(app, content_security_policy=csp, ...)
    and has not been moved inside a conditional block.
    """
    response = client.get('/nonexistent-route-csp-test-epic07')

    # The 404 handler returns a redirect — check CSP is on the redirect
    csp = response.headers.get('Content-Security-Policy')
    assert csp is not None, (
        "Content-Security-Policy header is missing from the 404/redirect response. "
        "Talisman may not be wrapping error responses, or may have been removed. "
        "Without CSP on all responses, an attacker who exploits a reflection "
        "vulnerability on an error page has no browser-level restriction on "
        "loading external scripts."
    )


def test_csp_header_present_on_static_404_response(client):
    """
    STORY 04 — Subtask 3 (static variant) / Risk: GET HACKED.

    Static file 404 responses pass through the original Flask handler
    (not the custom redirect handler). These bare 404 responses must still
    have Talisman's CSP header applied at the WSGI middleware level.

    This is a distinct code path from the redirect-based 404: the handler
    returns `e` (the original exception object), not a redirect. Middleware
    must still wrap this response.
    """
    response = client.get('/static/img/csp_test_missing_file_epic07.jpg')
    assert response.status_code == 404  # Precondition

    csp = response.headers.get('Content-Security-Policy')
    assert csp is not None, (
        "Content-Security-Policy header is missing from the static file 404 response. "
        "The 404 handler returns the original exception object for /static/ paths. "
        "Talisman must still wrap this response at the middleware level. "
        "If CSP is absent here, XSS on any error page involving static assets "
        "has no browser-level mitigation."
    )


# =============================================================================
# STORY 07 — SESSION_PERMANENT=False (Cookie Privacy)
# =============================================================================

def test_session_cookie_has_no_expires_or_max_age_attribute(client):
    """
    STORY 07 — Subtask 1 / Risk: GET HACKED (session persists after browser close).

    SESSION_PERMANENT=False must produce a Set-Cookie header with NO
    Expires and NO Max-Age attribute. This makes the cookie a "session cookie"
    — the browser deletes it when the user closes ALL windows.

    On a shared device (school computer, library, partner's laptop):
      - With Expires: the next person who opens the browser finds a live
        session. They navigate to /cartas and see the previous user's
        card selection. They navigate to /results and see the previous
        user's reading. This is a data breach on a shared device.
      - Without Expires: the browser discards the cookie on exit. The
        next user has no session and must start from the home page.

    How to check: The Set-Cookie header for a session cookie must NOT
    contain either `Expires=` or `Max-Age=`. If either is present,
    SESSION_PERMANENT has been accidentally set to True.

    Note: PERMANENT_SESSION_LIFETIME (the Redis TTL) is a server-side
    limit and is independent of the client-side cookie expiry. Both must
    be correct: the cookie must expire on browser close (client) AND the
    Redis key must expire in 30 minutes (server). This test covers the
    client-side half.
    """
    response = client.get('/')

    all_set_cookie = response.headers.getlist('Set-Cookie')
    session_cookies = [c for c in all_set_cookie if c.lower().startswith('session=')]

    assert session_cookies, (
        "No 'session' Set-Cookie header found after GET /. "
        "The session may not be initialising — check SESSION_TYPE='redis' "
        "and SESSION_COOKIE_NAME='session' in app.config."
    )

    cookie = session_cookies[0]

    assert 'Expires=' not in cookie, (
        f"Session cookie has an 'Expires=' attribute: '{cookie}'. "
        "This means SESSION_PERMANENT=True or the session interface is setting "
        "an explicit expiry. The cookie will persist on disk after the browser "
        "closes — on shared devices, the next user inherits this session. "
        "Fix: ensure SESSION_PERMANENT=False in app.config."
    )
    assert 'Max-Age=' not in cookie, (
        f"Session cookie has a 'Max-Age=' attribute: '{cookie}'. "
        "Same risk as Expires — the browser keeps this cookie between restarts. "
        "Fix: ensure SESSION_PERMANENT=False in app.config."
    )
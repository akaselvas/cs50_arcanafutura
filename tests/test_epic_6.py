# =============================================================================
# test_epic_06.py — Epic 06: Responsive Design & Device Compatibility
#
# Place this file in your tests/ folder alongside test_epic_01.py … 05.py.
#
# ─────────────────────────────────────────────────────────────────────────────
# FILTER RESULT: "If this breaks, will the app crash, get hacked, or cost money?"
# ─────────────────────────────────────────────────────────────────────────────
#
# Story 01 — Device Orientation (rotate-message overlay):
#   The #rotate-message div is shown/hidden via a CSS @media (orientation: landscape)
#   rule. pytest's HTTP test client has no viewport, no GPU, and runs no CSS engine.
#   There is no HTTP response attribute to assert against. Belongs in Playwright.
#   Filter verdict: ❌ (UX only — broken overlay is annoying, not a crash/breach)
#
# Story 02 — Mobile Keyboard Handling (Home Page):
#   The keyboard-active class is added to <body> by a JavaScript focus listener
#   that calls window.matchMedia("(hover: none) and (pointer: coarse)").matches.
#   This is evaluated inside the browser's JS engine. pytest cannot emulate a
#   touch device, open a virtual keyboard, or observe classList changes.
#   Filter verdict: ❌ (UX only — no server-side code is involved)
#
# Story 03 — Card Grid Responsiveness:
#   Flexbox wrapping behavior, scrollWidth, touch target size, and viewport meta
#   tag effects are all rendered by the browser's layout engine. Testing these
#   requires a headless browser that can measure element bounding boxes.
#   Filter verdict: ❌ (UX only — a broken grid is not a security issue)
#
# Story 04 — Touch Event Compatibility (Sticky Hover, 300ms delay):
#   Mobile tap-to-click translation, CSS :hover state persistence, and the
#   double-tap-to-zoom suppression via <meta name="viewport"> are all enforced
#   by the mobile browser/OS, not by Flask. These cannot be simulated via HTTP.
#   Filter verdict: ❌ (UX only — no server-side crash vector)
#
# ─────────────────────────────────────────────────────────────────────────────
# WHAT IS AUTOMATABLE IN THIS EPIC
# ─────────────────────────────────────────────────────────────────────────────
#
# Epic 06's updated code introduced /clear_session — a new backend route that
# the JavaScript tab-privacy guard in cartas.html and results.html calls via
# fetch() POST when sessionStorage.getItem('tab_active') is falsy (i.e., when
# the user opens a new tab or window without navigating from the home page):
#
#   fetch('/clear_session', { method: 'POST' }).then(() => {
#       window.location.href = '/';
#   });
#
# This route has genuine crash and data-breach risk that pytest CAN cover:
#
#   CRASH:       If /clear_session returns 500, the JS .catch() is never
#                triggered (fetch() resolves on any HTTP status). The browser
#                redirects to / anyway — but the session is not cleared. The
#                next user on a shared device (school computer, internet café)
#                inherits the previous user's intencao, selected_cards, and
#                choosed_cards from Redis.
#
#   DATA BREACH: If session.clear() silently fails (e.g., a future Redis
#                connection issue during the clear), the session data persists.
#                The subsequent GET / in the same browser then receives a fresh
#                CSRF token but the old session payload, meaning the new user
#                starts a game with someone else's pre-filled intention.
#
#   SECURITY:    The route is @csrf.exempt. If it ever accidentally accepts GET
#                requests, the exemption becomes a bypass surface — a link or
#                <img src="/clear_session"> on any page could clear another
#                user's session via CSRF, acting as a denial-of-service.
#
# These 4 tests cover the only server-side code introduced by Epic 06.
#
# ─────────────────────────────────────────────────────────────────────────────
# PLAYWRIGHT COVERAGE (out of scope for this file)
# ─────────────────────────────────────────────────────────────────────────────
#
# The following scenarios belong in a Playwright / Appium test suite:
#
#   playwright/test_epic_06_orientation.spec.js
#     - page.setViewportSize() to landscape → assert #rotate-message visible
#     - page.setViewportSize() to portrait  → assert #rotate-message hidden
#
#   playwright/test_epic_06_keyboard.spec.js
#     - page.tap('#intencao') → assert body.classList contains 'keyboard-active'
#     - page.tap('body')      → assert body.classList does NOT contain it
#
#   playwright/test_epic_06_grid.spec.js
#     - page.setViewportSize(320, 568) → assert no horizontal overflow
#     - page.locator('.card').first().boundingBox() → assert width >= 44
#
#   playwright/test_epic_06_touch.spec.js
#     - page.tap('.botao-personalizado[data-value="3"]') → assert active class
#     - assert no double-tap required (measure time from tap to animation start)
#
# =============================================================================

import pytest
from app import app


# =============================================================================
# FIXTURE
# =============================================================================

@pytest.fixture
def client():
    """Standard test client. CSRF disabled — /clear_session is @csrf.exempt anyway."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as c:
        yield c
    app.config['WTF_CSRF_ENABLED'] = True


# =============================================================================
# /clear_session ROUTE — Tab Privacy Guard
#
# Epic 06 introduced this route to support the sessionStorage-based tab
# detection added to cartas.html and results.html. It is the only new
# server-side code in the entire Epic, and it has three distinct risk vectors:
# crash, data breach, and method-restriction bypass.
# =============================================================================

def test_clear_session_post_returns_200_and_json_redirect(client):
    """
    Epic 06 — /clear_session POST / Risk: CRASH → DATA BREACH.

    This is the primary availability test for the tab privacy guard.

    The JavaScript in cartas.html and results.html calls:
        fetch('/clear_session', { method: 'POST' })
            .then(() => { window.location.href = '/'; });

    fetch() resolves (enters .then()) for ANY HTTP status code, including 500.
    This means: if /clear_session crashes with a 500, the browser STILL
    redirects to /. The user sees the home page as expected. The crash is
    completely invisible to them. But session.clear() never ran.

    On a shared device (school computer, library, internet café), the next
    person who opens a new tab to the app now inherits the previous user's:
      - intencao (their typed intention, potentially personal/sensitive)
      - selected_cards (their game state)
      - choosed_cards (stored after /results POST)
      - reading_cache Redis key (the full AI reading from the previous session)

    This is a silent data breach that produces no error in any log visible
    to the affected users.
    """
    # Establish a session with sensitive data
    client.post('/process_form', data={
        'intencao':     'Sensitive personal intention',
        'selectedCards': '3'
    })

    response = client.post('/clear_session')

    assert response.status_code == 200, (
        f"/clear_session returned {response.status_code} instead of 200. "
        "The JavaScript fetch().then() callback still fires, so the user is "
        "redirected to / with no visible error. But session.clear() did not run. "
        "The next user on this device inherits the previous user's session data "
        "from Redis — a silent data breach."
    )
    assert response.content_type == 'application/json', (
        f"Expected application/json but got '{response.content_type}'. "
        "The JS reads data.redirect from the JSON body to navigate. "
        "A non-JSON response means window.location.href is never set "
        "and the redirect silently fails."
    )
    data = response.get_json()
    assert 'redirect' in data, (
        f"Response JSON is missing the 'redirect' key: {data}. "
        "The frontend JS does: window.location.href = data.redirect. "
        "Without this key, the redirect fails silently."
    )
    assert data['redirect'] == '/', (
        f"Expected redirect to '/' but got '{data['redirect']}'. "
        "The user should be sent back to the home page after session clear."
    )


def test_clear_session_actually_clears_all_session_keys(client):
    """
    Epic 06 — /clear_session POST / Risk: DATA BREACH.

    Verifies that session.clear() removes ALL session keys, not just
    specific ones. This guards against a future refactor that accidentally
    changes the route to session.pop('intencao', None) — which would leave
    selected_cards and choosed_cards intact, still leaking game state.

    This is the most critical test in Epic 06: even if the route returns
    200, the data is only safe if the session is actually empty afterward.
    """
    # Write all three sensitive keys into the session
    client.post('/process_form', data={
        'intencao':     'Sensitive data that must be erased',
        'selectedCards': '5'
    })
    with client.session_transaction() as sess:
        sess['choosed_cards'] = [{"name": "O Louco", "value": "normal"}]
        sess['reading_cache'] = 'Full AI reading text'  # simulate cached reading

    # Verify data is actually present before the clear
    with client.session_transaction() as sess:
        assert 'intencao' in sess, "Precondition failed: session not populated before clear"
        assert 'selected_cards' in sess

    # Execute the clear
    response = client.post('/clear_session')
    assert response.status_code == 200

    # Verify the session is empty afterward
    with client.session_transaction() as sess:
        assert sess.get('intencao') is None, (
            "session['intencao'] still present after /clear_session. "
            "The next user on a shared device can read the previous user's intention."
        )
        assert sess.get('selected_cards') is None, (
            "session['selected_cards'] still present after /clear_session. "
        )
        assert sess.get('choosed_cards') is None, (
            "session['choosed_cards'] still present after /clear_session. "
            "The next user starts with pre-selected cards from the previous user's game."
        )
        # Verify the session dict is fully empty, not just the known keys
        assert len(dict(sess)) == 0, (
            f"Session is not fully empty after /clear_session: {dict(sess)}. "
            "Unknown keys may contain sensitive residual data."
        )


def test_clear_session_rejects_get_request(client):
    """
    Epic 06 — /clear_session method restriction / Risk: DENIAL OF SERVICE via CSRF.

    The route is @csrf.exempt to allow the tab guard to POST without a token.
    This exemption is safe ONLY because the route exclusively accepts POST.

    If GET were ever accidentally added (e.g., methods=['GET', 'POST']):
      - The @csrf.exempt exemption means no CSRF token is required.
      - Any external page can embed <img src="https://yourapp.com/clear_session">
        or <a href="/clear_session"> and the victim's browser sends a GET
        request when loading the page or clicking the link.
      - This silently clears the authenticated user's session mid-reading,
        destroying their in-progress tarot reading and forcing them back to /.
      - This is a CSRF-based Denial of Service: no token is required because
        the route explicitly exempts itself.

    Flask returns 405 for method mismatches — this test verifies that
    behavior is enforced.
    """
    response = client.get('/clear_session')
    assert response.status_code == 405, (
        f"/clear_session accepted a GET request (status: {response.status_code}). "
        "The route is @csrf.exempt, so a GET from any external page silently "
        "clears the user's session mid-reading without any token required. "
        "Fix: verify the route decorator is @app.route('/clear_session', methods=['POST']) "
        "with POST only — never methods=['GET', 'POST']."
    )


def test_clear_session_is_csrf_exempt_and_post_succeeds_without_token():
    """
    Epic 06 — /clear_session / Risk: CRASH (without exemption, every tab
    guard POST would fail with 400 CSRF error).

    The JS tab guard fires immediately on page load:
        fetch('/clear_session', { method: 'POST' })

    At this point in the page lifecycle, the JS has no access to a CSRF
    token — the form hasn't rendered yet, and the meta tag is only in
    results.html, not cartas.html. The route MUST be @csrf.exempt or every
    tab-guard POST fails with a 400 CSRF error, and the redirect to / never
    executes, leaving the user stuck on a page with stale session data.

    This test verifies the exemption is in place by deliberately sending a
    POST with NO csrf_token and asserting a 200, not a 400.
    """
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = True  # Deliberately enable CSRF for this test

    with app.test_client() as csrf_client:
        # POST with no CSRF token — would return 400 on any non-exempt route
        response = csrf_client.post('/clear_session')  # no data, no token

    app.config['WTF_CSRF_ENABLED'] = False

    assert response.status_code == 200, (
        f"/clear_session returned {response.status_code} when called without a "
        f"CSRF token (CSRF enabled). Expected 200 because the route is @csrf.exempt. "
        "If this returns 400, the @csrf.exempt decorator has been removed. "
        "The JS tab guard fires before any token is available on the page, "
        "so every call would fail → session is never cleared → data breach on "
        "shared devices. Fix: restore @csrf.exempt on the /clear_session route."
    )
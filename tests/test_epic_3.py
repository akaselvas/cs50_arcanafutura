import pytest
from unittest.mock import MagicMock, patch
from markupsafe import Markup
from app import markdown_to_html, generate_tarot_reading

# =============================================================================
# EPIC 03 — AI Reading Generation (WebSocket Reliability)
#
# Copy and paste everything below this line into your existing test_app.py.
# The `client` fixture is already defined in Epic 01.
#
# Scope of automation:
#   - Unit tests on `markdown_to_html` and `generate_tarot_reading` — these
#     are pure Python functions we can test directly without a browser or a
#     live WebSocket. All WebSocket interaction, DOM transitions, and scroll
#     behavior belong in Playwright and are NOT included here.
#   - Story 02 (AI content quality) is NOT automated — LLM output is
#     non-deterministic and requires human judgment. Running it in CI would
#     also make real Gemini API calls, costing money on every test run.
# =============================================================================




# =============================================================================
# STORY 01 — Markdown to HTML Rendering
# Risk category: COSTS MONEY
# If markdown_to_html breaks or produces garbage, the Gemini API call was
# already made and paid for. The user gets a broken result they can't read.
# =============================================================================

def test_markdown_to_html_converts_bold_text():
    """
    STORY 01 — Subtask 4.
    The AI model outputs **Card Name** (Markdown bold). If conversion breaks,
    the user sees raw asterisks: **O Mago** instead of <strong>O Mago</strong>.
    The reading is still generated (money spent), just unreadable.
    """
    result = markdown_to_html("**O Mago** é uma carta de poder.")
    html = str(result)
    assert '<strong>' in html, "Bold markdown (**) must convert to <strong> tag"
    assert '**' not in html, "Raw markdown asterisks must not appear in output"
    assert 'O Mago' in html


def test_markdown_to_html_converts_unordered_lists():
    """
    STORY 01 — Subtask 4.
    The AI frequently returns bulleted lists for card meanings. If list
    conversion breaks, all items collapse into a single unreadable line.
    """
    result = markdown_to_html("Significados:\n- Início\n- Aventura\n- Liberdade")
    html = str(result)
    assert '<ul>' in html, "Markdown list (-) must convert to <ul> tag"
    assert '<li>' in html, "Each list item must be wrapped in <li>"
    assert '-' not in html or html.count('-') < html.count('<li>'), \
        "Raw markdown dashes must be replaced by <li> elements"


def test_markdown_to_html_converts_headers():
    """
    STORY 01 — Subtask 4.
    The AI uses headers to separate card sections (## O Mago). If header
    conversion breaks, the reading is a wall of unseparated text.
    """
    result = markdown_to_html("## A Leitura\n\nTexto aqui.")
    html = str(result)
    assert '<h2>' in html, "Markdown ## must convert to <h2>"
    assert '##' not in html, "Raw ## must not appear in output"


def test_markdown_to_html_converts_italic_text():
    """
    STORY 01 — Subtask 4.
    The AI uses *italic* for card orientations ("*invertida*"). Raw asterisks
    in the UI look like a broken template, not a mystical reading.
    """
    result = markdown_to_html("A carta está *invertida*, indicando bloqueio.")
    html = str(result)
    assert '<em>' in html, "Markdown *text* must convert to <em> tag"
    assert result.count('*') == 0, "Raw asterisks must not appear in the output"


def test_markdown_to_html_returns_markup_type():
    """
    STORY 01 — Regression guard.
    The function must return a `markupsafe.Markup` object, not a plain string.
    If it ever returns a plain str, Jinja2 will HTML-escape the entire output —
    the user sees &lt;strong&gt; entities instead of bold text.
    This is silent: the page loads fine but all formatting is destroyed.
    """
    result = markdown_to_html("**teste**")
    assert isinstance(result, Markup), (
        "markdown_to_html must return markupsafe.Markup, not str. "
        "Without this, Jinja2 escapes the HTML and the user sees raw entities."
    )


def test_markdown_to_html_handles_empty_string_without_crash():
    """
    STORY 01 — Subtask 5 / crash guard.
    An empty string is a valid edge case (e.g., if the AI returns whitespace
    only and the calling code strips it before passing here). The function
    must return an empty Markup, not throw an exception.
    """
    try:
        result = markdown_to_html("")
        assert isinstance(result, Markup)
    except Exception as e:
        pytest.fail(f"markdown_to_html('') raised an exception: {e}")


def test_markdown_to_html_handles_plain_text_without_crash():
    """
    STORY 01 — Subtask 5 / crash guard.
    Plain text with no markdown syntax must pass through as a paragraph
    without any exception, returning valid HTML.
    """
    try:
        result = markdown_to_html("Uma leitura simples sem formatação especial.")
        assert 'Uma leitura simples' in str(result)
    except Exception as e:
        pytest.fail(f"markdown_to_html raised an exception on plain text: {e}")


# =============================================================================
# STORY 01 — Subtask 6: XSS via AI Output
# Risk category: GET HACKED
#
# IMPORTANT — THIS TEST IS MARKED xfail BECAUSE IT DOCUMENTS A KNOWN,
# CURRENTLY UNFIXED VULNERABILITY.
#
# Root cause: `markdown_to_html` uses `Markup()` which only tells Jinja2
# "don't escape this string." It does NOT strip or sanitize the content.
# The Python `markdown` library passes raw HTML through unchanged.
# If Gemini returns <script>...</script> in its response (via prompt injection),
# the script tag survives all the way to the browser's .innerHTML call in
# results.html, where it executes.
#
# Required fix: Run the output of markdown.markdown() through
# bleach.clean(..., tags=ALLOWED_HTML_TAGS, strip=True) BEFORE wrapping
# in Markup(), so script tags are stripped from the AI output.
#
# When the fix is applied, this test will become an xpass (unexpected pass),
# which serves as your signal to remove the xfail marker.
# =============================================================================

@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN SECURITY VULNERABILITY (Story 01 - Subtask 6): "
        "markdown_to_html does not sanitize AI output. "
        "<script> tags survive the conversion pipeline and would execute "
        "in the browser via .innerHTML injection in results.html. "
        "Fix: apply bleach.clean() on the markdown output BEFORE Markup(). "
        "Remove this xfail marker once the fix is deployed."
    )
)
def test_markdown_to_html_strips_script_tags_from_ai_output():
    """
    STORY 01 — Subtask 6 (XSS via AI Output).

    This test asserts the DESIRED SECURE BEHAVIOR: that script tags injected
    via prompt manipulation are stripped before the HTML reaches the browser.

    The test currently FAILS (xfail) because the vulnerability is unfixed.
    When markdown_to_html is hardened with bleach, it will pass.
    """
    malicious_ai_output = (
        "## Sua Leitura\n\n"
        "O Louco representa novos começos.\n\n"
        "<script>alert('AI-XSS')</script>"
    )
    result = markdown_to_html(malicious_ai_output)
    html = str(result)

    # This is the SECURE state we want — script tags stripped, content preserved
    assert '<script>' not in html, (
        "VULNERABILITY CONFIRMED: <script> tag survived markdown_to_html. "
        "This output is injected via .innerHTML in results.html and WILL execute."
    )
    assert 'O Louco' in html, "Legitimate reading content must be preserved after sanitization"


# =============================================================================
# STORY 03 — API Error & Timeout Handling
# Risk category: CRASH
#
# We mock `model.generate_content` at the module level using unittest.mock.
# This lets us simulate API failures (invalid key, timeout, safety rejection)
# without making real API calls or spending quota.
#
# The key insight from reading app.py:
# - `generate_tarot_reading` raises exceptions — it does NOT return fallback text.
# - The `background_generate` closure inside `handle_generation` catches them.
# - So the test contract is: the function must RAISE on failure, not swallow it.
#   Swallowing the exception would cause background_generate to emit
#   generation_complete with None as the reading — a silent crash in the browser.
# =============================================================================

VALID_CARDS = [
    {"name": "O Louco", "value": "normal"},
    {"name": "A Torre", "value": "invertido"},
    {"name": "O Sol", "value": "normal"},
]


def test_generate_tarot_reading_raises_on_api_exception():
    """
    STORY 03 — Subtasks 1 & 2 (API failure / timeout).
    When model.generate_content raises any Exception (invalid key, timeout,
    network error, quota exceeded), generate_tarot_reading must propagate it.
    If it catches and swallows the exception silently, background_generate
    emits `generation_complete` with None as the reading → TypeError in the
    browser when it tries to inject None into the DOM.
    """
    mock_response = MagicMock()
    mock_response.text = "Texto de leitura válido"

    with patch('app.model.generate_content', side_effect=Exception("Simulated API failure")):
        with pytest.raises(Exception, match="Simulated API failure"):
            generate_tarot_reading("test", "3", VALID_CARDS)


def test_generate_tarot_reading_raises_on_timeout():
    """
    STORY 03 — Subtask 2 (timeout simulation).
    A TimeoutError (e.g., Gemini takes >30s) must propagate so the background
    task can catch it and emit generation_error to the client. If it hangs
    silently, the user stares at the loading dots forever.
    """
    with patch('app.model.generate_content', side_effect=TimeoutError("Gemini timeout")):
        with pytest.raises(TimeoutError):
            generate_tarot_reading("test", "3", VALID_CARDS)


def test_generate_tarot_reading_raises_on_empty_api_response():
    """
    STORY 03 — Subtasks 1, 2, 3 (empty/blocked response).
    When the Gemini API returns a response but with no text (e.g., the safety
    filter blocked the output), response.text is empty. The function explicitly
    raises ValueError("A API retornou uma resposta vazia.").
    If this guard is removed, markdown_to_html('') is called → returns empty
    Markup → user sees a blank result area after the AI call already cost money.
    """
    mock_response = MagicMock()
    mock_response.text = ""  # Safety block returns empty text

    with patch('app.model.generate_content', return_value=mock_response):
        with pytest.raises(ValueError, match="A API retornou uma resposta vazia"):
            generate_tarot_reading("test", "3", VALID_CARDS)


def test_generate_tarot_reading_raises_on_none_response_text():
    """
    STORY 03 — Edge case variant.
    Some Gemini SDK versions return None for response.text instead of
    an empty string when output is blocked. `if not response.text` catches both,
    but this test explicitly guards against the None case being re-introduced
    if the condition is ever changed to `if response.text == ""`.
    """
    mock_response = MagicMock()
    mock_response.text = None

    with patch('app.model.generate_content', return_value=mock_response):
        with pytest.raises((ValueError, TypeError)):
            generate_tarot_reading("test", "3", VALID_CARDS)


def test_generate_tarot_reading_succeeds_on_valid_response():
    """
    STORY 03 — Regression guard (happy path with mock).
    Verifies the full success path: model returns text → markdown_to_html
    converts it → Markup is returned. If any step in this chain is broken,
    the happy path fails for every user even when the API is working.
    This test costs $0 (mocked) and runs in <1ms.
    """
    mock_response = MagicMock()
    mock_response.text = "## O Louco\n\nUma carta de **novos começos**."

    with patch('app.model.generate_content', return_value=mock_response):
        result = generate_tarot_reading("Minha intenção", "3", VALID_CARDS)

    assert result is not None, "generate_tarot_reading must not return None on success"
    assert isinstance(result, Markup), "Result must be Markup so Jinja2 renders HTML, not escaped text"
    assert '<strong>' in str(result), "Markdown must be converted to HTML in the returned value"


def test_generate_tarot_reading_includes_cards_in_prompt():
    """
    STORY 03 / STORY 02 — Subtask 6 (data integrity, automatable part).
    The card names MUST be included in the prompt sent to the AI. This is
    the only part of Story 02's data integrity tests we can automate without
    a live API — we intercept the actual call and inspect the prompt argument.
    If cards are silently dropped from the prompt, the AI hallucinates or
    gives a generic reading. Money was spent; the user got garbage.
    """
    mock_response = MagicMock()
    mock_response.text = "Leitura de teste."

    with patch('app.model.generate_content', return_value=mock_response) as mock_call:
        generate_tarot_reading("Quero saber sobre meu futuro", "3", VALID_CARDS)

    # Inspect the prompt that was actually passed to the API
    assert mock_call.called, "model.generate_content was never called"
    actual_prompt = mock_call.call_args[0][0]  # First positional argument

    assert "O Louco" in actual_prompt, \
        "Card name 'O Louco' is missing from the AI prompt — AI cannot read a card it doesn't know about"
    assert "A Torre" in actual_prompt, \
        "Card name 'A Torre' is missing from the AI prompt"
    assert "O Sol" in actual_prompt, \
        "Card name 'O Sol' is missing from the AI prompt"
    assert "invertido" in actual_prompt, \
        "Card orientation 'invertido' is missing from the prompt — AI will give wrong reversed reading"
    assert "Quero saber sobre meu futuro" in actual_prompt, \
        "User intention is missing from the AI prompt — reading will be generic, not personalized"


def test_generate_tarot_reading_with_empty_intention_does_not_crash():
    """
    STORY 01 — Subtask 5 / STORY 03 — crash guard.
    The intention field is optional. An empty string must produce a valid
    prompt and a valid result. If any string interpolation in the prompt
    fails on an empty value (e.g., a future refactor uses .format() without
    a default), this test catches the regression before it reaches production.
    """
    mock_response = MagicMock()
    mock_response.text = "Leitura sem intenção específica."

    with patch('app.model.generate_content', return_value=mock_response):
        try:
            result = generate_tarot_reading("", "3", VALID_CARDS)
            assert result is not None
        except Exception as e:
            pytest.fail(
                f"generate_tarot_reading crashed with an empty intention: {e}. "
                "The intention field is optional — empty string must be handled."
            )


def test_generate_tarot_reading_with_empty_cards_does_not_crash():
    """
    STORY 03 — Edge case / crash guard.
    If the /results route's JSON fallback fires (malformed payload → choosed_cards=[]),
    generate_tarot_reading is called with an empty list. json.dumps([]) is valid,
    so the prompt is built and sent to the API. This should not raise a crash —
    it's a logic bug (wasted API call), not a runtime error.
    This test guards against a future refactor that adds len(choosed_cards) > 0
    assertion and starts raising instead of gracefully sending an empty prompt.
    """
    mock_response = MagicMock()
    mock_response.text = "Leitura genérica sem cartas específicas."

    with patch('app.model.generate_content', return_value=mock_response):
        try:
            result = generate_tarot_reading("test", "3", [])
            assert result is not None
        except Exception as e:
            pytest.fail(
                f"generate_tarot_reading crashed with an empty cards list: {e}. "
                "This wasted an API call but must not crash — the /results route already "
                "handles this case by saving [] to the session."
            )
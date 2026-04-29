# =============================================================================
# app.py — Tarot Reading Web App (CS50 Final Project)
#
# A Flask web application that lets users draw tarot cards and receive AI-
# generated readings using Google's Gemma model. Features real-time streaming
# via WebSockets (Socket.IO), Redis-backed sessions, CSRF protection, and
# rate limiting. Designed to run both locally and on Render (production).
# =============================================================================

# gevent monkey-patching must happen BEFORE any other imports.
# It replaces Python's standard blocking I/O with non-blocking equivalents,
# which is required for Flask-SocketIO to work correctly with the gevent async mode.
from gevent import monkey
monkey.patch_all()

import json
import logging
import os
import random
import secrets
from typing import Any, Dict, List, Optional
import google.generativeai as genai
import markdown
import redis
import bleach
import threading
from datetime import timedelta
from dotenv import load_dotenv
from flask import (Flask, flash, redirect, render_template, request,
                   session, url_for, g, jsonify)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
from flask_socketio import SocketIO, emit
from flask_talisman import Talisman
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_wtf.csrf import generate_csrf
from flask_wtf.csrf import validate_csrf
from wtforms.validators import ValidationError
from markupsafe import Markup
from werkzeug.middleware.proxy_fix import ProxyFix

import time
from collections import defaultdict

# Load environment variables from the .env file (API keys, secret key, Redis URL, etc.)
load_dotenv()

# Configure logging so all INFO-level events are printed with a timestamp.
# This is useful for debugging and monitoring the app in production.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- App & WebSocket Initialization ---
app = Flask(__name__)

# ProxyFix tells Flask to trust the forwarded headers from Render's reverse proxy.
# Without this, Flask would see the proxy's IP instead of the real client's IP,
# which would break rate limiting and HTTPS detection.
# app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1, x_host=1, x_prefix=1)

# Detect whether we're running on Render's production environment.
# The RENDER env variable is automatically set by the platform.
is_production = os.environ.get('RENDER') is not None

# Initialize Socket.IO for real-time, bidirectional communication with the browser.
# In production, ONLY allow connections from the official Render URL.
# In development, allow '*' so local tools (BrowserSync, etc.) work.
allowed_origins = ["https://arcanafutura.onrender.com"] if is_production else "*"
socketio = SocketIO(app, cors_allowed_origins=allowed_origins, async_mode="gevent")


# --- Secret Key Validation ---
# The secret key is used by Flask to cryptographically sign sessions and CSRF tokens.
# We raise an error at startup rather than failing silently later.
secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    raise ValueError("No SECRET_KEY set for Flask application")

# --- Flask & Session Configuration ---
app.config.update(
    SECRET_KEY=secret_key,

    # Store sessions in Redis (server-side) instead of the default client-side cookie.
    # This prevents users from tampering with session data.
    SESSION_TYPE='redis',
    SESSION_PERMANENT=False,       # Session expires when the browser is closed
    SESSION_USE_SIGNER=True,       # Cryptographically signs the session cookie ID

    # Only require HTTPS for session cookies in production.
    # Forcing HTTPS locally would break development on http://localhost.
    SESSION_COOKIE_SECURE=is_production,

    SESSION_COOKIE_HTTPONLY=True,  # Prevents JavaScript from reading the session cookie (XSS defense).
    SESSION_COOKIE_SAMESITE='Lax', # Helps prevent CSRF by restricting cross-site cookie sending
    SESSION_COOKIE_NAME='session',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # Auto-expire sessions after 30 minutes of inactivity

    # CSRF token settings: tokens expire after 30 minutes, matching the session lifetime.
    WTF_CSRF_TIME_LIMIT=1800,
    WTF_CSRF_SSL_STRICT=False,     # Don't require HTTPS for CSRF validation (needed for local dev)
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_METHODS=['POST', 'PUT', 'PATCH', 'DELETE']  # Only protect state-changing HTTP methods
)

# Disable static file caching during development so changes are reflected immediately.
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# --- Redis Setup ---
# # Redis is used for two purposes: storing server-side sessions and tracking rate limit counters.
# redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379')
# app.config['SESSION_REDIS'] = redis.from_url(redis_url)
# redis_client = redis.Redis.from_url(redis_url)

# # --- Security Extensions ---

# # CSRF protection: Flask-WTF automatically generates and validates hidden tokens
# # in forms, preventing Cross-Site Request Forgery attacks.
# csrf = CSRFProtect(app)

# # Server-side session storage backed by Redis.
# Session(app)

# # Rate limiter: restricts how many requests a single IP can make.
# # Uses Redis to persist counters across requests (and server restarts).
# limiter = Limiter(
#     get_remote_address,
#     app=app,
#     storage_uri=redis_url,
#     storage_options={"socket_connect_timeout": 30},
#     strategy="fixed-window",
#     default_limits=["400 per day", "100 per hour"]
# )

# --- Redis Setup V2 with limiter---
redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379')

# 1. Create a connection pool for Flask-Session (Max 10 connections)
pool = redis.ConnectionPool.from_url(redis_url, max_connections=10)
redis_client = redis.Redis(connection_pool=pool)
app.config['SESSION_REDIS'] = redis_client

# --- Security Extensions ---
csrf = CSRFProtect(app)
Session(app)

# 2. Configure Limiter to manage its own connections (Max 10 connections)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=redis_url,
    # Pass max_connections as a setting, NOT the pool object!
    storage_options={"socket_connect_timeout": 30, "max_connections": 10}, 
    strategy="fixed-window",
    default_limits=["400 per day", "100 per hour"]
)

# --- Content Security Policy (CSP) ---
# CSP is a browser security feature that restricts which sources of content
# (scripts, styles, fonts, etc.) the browser is allowed to load.
# This significantly reduces the risk of XSS attacks.
csp = {
    'default-src': "'self'",
    'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://fonts.gstatic.com"],
    'script-src': ["'self'", "https://cdnjs.cloudflare.com"],
    'font-src': ["'self'", "https://fonts.googleapis.com", "https://fonts.gstatic.com"],
    'img-src': ["'self'", "data:"],
    'connect-src': ["'self'", "wss:", "ws:"]
}

# In local development, extend the CSP to allow connections from BrowserSync,
# Responsively App, and other local dev tools that run on different ports.
if not is_production:
    csp['script-src'] += [
        "http://localhost:3000",
        "http://192.168.0.102:3000",
        "https://localhost:*",
        "http://localhost:*"
    ]
    csp['img-src'] += [
        "http://localhost:3000",
        "http://192.168.0.102:3000"
    ]
    csp['connect-src'] += [
        "http://localhost:5000",     "ws://localhost:5000",
        "http://localhost:3000",     "ws://localhost:3000",
        "http://192.168.0.102:5000", "ws://192.168.0.102:5000",
        "http://192.168.0.102:3000", "ws://192.168.0.102:3000",
        "https://localhost:*",       "wss://localhost:*"
    ]

# Apply the CSP via Flask-Talisman, which also adds other security headers
# like HSTS (HTTP Strict Transport Security) and X-Content-Type-Options.
Talisman(app, content_security_policy=csp, content_security_policy_nonce_in=['script-src'])


# --- WebSocket Chat Rate Limiter ---
# Flask-Limiter only works on HTTP routes, so it cannot protect Socket.IO event
# handlers. This in-memory sliding window limiter fills that gap for the chat.
#
# A sliding window (vs. a fixed window) means the limit is always calculated
# against the last 60 seconds from RIGHT NOW, so a user can't game it by
# sending 10 messages at 1:59 and another 10 at 2:00.
#
# Why in-memory instead of Redis?
# The Redis connection pool is capped at 10 connections and is already shared
# between Flask-Session and Flask-Limiter. Checking Redis on every chat message
# risks starving the pool under load. An in-memory dict has zero connection cost.
#
# Trade-off: the counter resets on server restart and is not shared across
# multiple workers. Acceptable for this single-instance deployment on Render.
_message_timestamps: dict = defaultdict(list)
_MESSAGE_LIMIT = 10   # max messages allowed per user
_MESSAGE_WINDOW = 60  # rolling window in seconds

def is_rate_limited(session_id: str) -> bool:
    """
    Returns True if the given session (or IP, as fallback) has exceeded
    _MESSAGE_LIMIT messages within the last _MESSAGE_WINDOW seconds.
    Also cleans up the dict entry for idle users to prevent memory growth.
    """
    now = time.time()
    window_start = now - _MESSAGE_WINDOW

    # Discard timestamps that have fallen outside the rolling window.
    _message_timestamps[session_id] = [
        t for t in _message_timestamps[session_id] if t > window_start
    ]

    # If the list is now empty, the user has been idle — remove the entry
    # entirely so the dict doesn't grow unbounded over the server's lifetime.
    if not _message_timestamps[session_id]:
        _message_timestamps.pop(session_id, None)

    # Reject the request if the user has hit the limit.
    if len(_message_timestamps.get(session_id, [])) >= _MESSAGE_LIMIT:
        return True

    # Otherwise, record this message's timestamp and allow it through.
    _message_timestamps.setdefault(session_id, []).append(now)
    return False

# --- Input Sanitization ---
def sanitize_input(text: str) -> str:
    """
    Strips ALL HTML tags from user-provided text using the bleach library.
    This ensures the intention is stored as plain text only, preventing 
    XSS attacks and removing unnecessary formatting.
    """
    # allowed_tags = ['a', 'b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'li', 'ol',
                    # 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'pre', 'code']
    # allowed_attributes = {'a': ['href', 'rel']}
    cleaned_text = bleach.clean(text, tags=[], attributes={}, strip=True)
    return cleaned_text


def markdown_to_html(text: str) -> Markup:
    """
    Converts Markdown-formatted text (returned by the AI model) into safe HTML.
    The result is wrapped in Markup so Jinja2 renders it as raw HTML instead of
    escaping it, which is safe here since the content comes from our own AI model.
    """
    return Markup(markdown.markdown(text, extensions=['fenced_code', 'codehilite']))


# --- CSRF Error Handler ---
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """
    Handles CSRF validation failures gracefully.
    AJAX requests get a JSON error response; regular form submissions get a
    flash message and are redirected back to the home page.
    """
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'error': 'CSRF token validation failed. Please refresh the page.',
            'success': False
        }), 400
    else:
        flash('Security token has expired. Please try again.', 'error')
        return redirect(url_for('home'))


@app.before_request
def before_request():
    """
    Runs before every request. Generates a unique cryptographic nonce
    and stores it in Flask's 'g' object (per-request global storage).
    The nonce can be used in templates for inline script tags to comply
    with a strict CSP without needing 'unsafe-inline'.
    """
    # g.nonce = secrets.token_hex(16)


# --- AI Model Setup ---
# Load the Gemini API key from environment variables and fail fast if it's missing.
api_key = os.getenv("GENAI_API_KEY")
if not api_key:
    raise EnvironmentError("Missing GENAI_API_KEY environment variable.")

genai.configure(api_key=api_key, transport='rest')

# Generation config controls the AI's output style:
# - temperature: creativity level (higher = more random)
# - top_p / top_k: sampling strategies to avoid repetitive or low-quality output
# - max_output_tokens: caps the response length to avoid runaway costs
generation_config = {
    "temperature": 0.7,
    "top_p": 0.95,
    "top_k": 30,
    "max_output_tokens": 1000,
}

# Initialize the Gemma 3 model (a lightweight, open-weights model from Google).
model = genai.GenerativeModel(
    model_name="gemma-3-12b-it",
    generation_config=generation_config
)


# --- Tarot Card Deck ---
# A static list of the 22 Major Arcana cards, each with a display name and
# the path to its image in the static folder. This list is never modified at runtime.
TAROT_CARDS: List[Dict[str, str]] = [
        {"image": "/static/img/a01.jpg", "name": "O Mago"},
        {"image": "/static/img/a02.jpg", "name": "A Papisa"},
        {"image": "/static/img/a03.jpg", "name": "A Imperatriz"},
        {"image": "/static/img/a04.jpg", "name": "O Imperador"},
        {"image": "/static/img/a05.jpg", "name": "O Papa"},
        {"image": "/static/img/a06.jpg", "name": "Os Namorados"},
        {"image": "/static/img/a07.jpg", "name": "O Carro"},
        {"image": "/static/img/a08.jpg", "name": "A Justiça"},
        {"image": "/static/img/a09.jpg", "name": "O Eremita"},
        {"image": "/static/img/a10.jpg", "name": "A Roda da Fortuna"},
        {"image": "/static/img/a11.jpg", "name": "A Força"},
        {"image": "/static/img/a12.jpg", "name": "O Enforcado"},
        {"image": "/static/img/a13.jpg", "name": "Morte"},
        {"image": "/static/img/a14.jpg", "name": "A Temperança"},
        {"image": "/static/img/a15.jpg", "name": "O Diabo"},
        {"image": "/static/img/a16.jpg", "name": "A Torre"},
        {"image": "/static/img/a17.jpg", "name": "A Estrela"},
        {"image": "/static/img/a18.jpg", "name": "A Lua"},
        {"image": "/static/img/a19.jpg", "name": "O Sol"},
        {"image": "/static/img/a20.jpg", "name": "O Julgamento"},
        {"image": "/static/img/a21.jpg", "name": "O Mundo"},
        {"image": "/static/img/a22.jpg", "name": "O Louco"},
    ]


# --- WTForms Form Class ---
class TarotForm(FlaskForm):
    """
    A minimal Flask-WTF form used solely to generate and validate CSRF tokens.
    Flask-WTF automatically adds a hidden 'csrf_token' field to this form,
    which must be submitted with every POST request to prove the request
    originated from our own page and not a malicious third-party site.
    """
    class Meta:
        csrf = True


# =============================================================================
# ROUTES
# =============================================================================
@app.route('/clear_session', methods=['POST'])
@csrf.exempt  # Safe here: this route only destroys data, it never writes or reads sensitive state
def clear_session():
    session.clear()
    return jsonify({'redirect': url_for('home')})


@app.route('/')
def home():
    """
    Renders the landing page where the user enters their intention and
    selects how many cards to draw (1, 3, or 5).
    A TarotForm instance is passed to the template so the CSRF token
    hidden field is available in the HTML form.
    """
    # Clear cache ONLY on the home page
    # session_id = request.cookies.get('session')
    # if session_id:
    #     redis_client.delete(f"reading_cache:{session_id}")
    #     redis_client.delete(f"chat_history:{session_id}")

    session.pop('intencao', None)
    session.pop('selected_cards', None)
    session.pop('choosed_cards', None)

    client_ip = get_remote_address()
    logging.info(f"QA DEBUG: Home page accessed by IP: {client_ip}")
    
    form = TarotForm()
    return render_template('index.html', form=form)


@app.route('/process_form', methods=['POST'])
def process_form():
    """
    Handles the home page form submission.

    1. Validates the CSRF token via Flask-WTF.
    2. Sanitizes the user's intention text to strip any injected HTML.
    3. Validates the number of cards selected (must be 1, 3, or 5).
    4. Saves both values to the server-side session for use in later routes.
    5. Returns a JSON redirect URL so the frontend can navigate the user
       to the card selection page (/cartas) without a full page reload.
    """
    form = TarotForm()

    if not form.validate_on_submit():
        if form.csrf_token.errors:
            logging.warning(f"CSRF Error: {form.csrf_token.errors}")
            return jsonify({'error': 'Invalid CSRF token'}), 400
        return jsonify({'error': 'Form validation failed'}), 400

    intencao = sanitize_input(request.form.get('intencao', '').strip())
    selected_cards = request.form.get('selectedCards')

    logging.info(f"QA DEBUG: selected_cards value is '{selected_cards}' and type is {type(selected_cards)}")

    # Validate the card count against the allowed options to prevent manipulation.
    if not selected_cards or selected_cards not in ['1', '3', '5']:
        return jsonify({'error': 'Invalid card selection'}), 400

    # Cap the intention length to avoid overly long prompts being sent to the AI.
    if len(intencao) > 400:
        return jsonify({'error': 'Intention too long'}), 400

    session['intencao'] = intencao
    session['selected_cards'] = selected_cards

    session.pop('choosed_cards', None)

    # =====================================================================
    # Clear the old reading cache here!
    # Because POST requests are never cached by the browser, this guarantees
    # the old reading is wiped out the exact moment a NEW game starts.
    # =====================================================================
    session_id = request.cookies.get('session')
    if session_id:
        redis_client.delete(f"reading_cache:{session_id}")
        redis_client.delete(f"chat_history:{session_id}")

    return jsonify({'redirect': url_for('cartas')})


@app.route('/cartas')
def cartas():
    """
    Renders the card selection page where the user picks their cards.
    The full 22-card deck is shuffled and each card is randomly assigned
    an orientation ('normal' or 'invertido'), which influences the AI reading.
    The deck is split into 3 visual groups for the UI layout, and the
    number of cards the user should pick is passed to the template.
    """
    raw_val = session.get('selected_cards')
    if raw_val not in ['1', '3', '5']:
        return redirect(url_for('home'))
        
    selected_cards = int(raw_val)
    choosed_cards = session.get('choosed_cards', [])

    # If they already picked cards, we need to attach the image URLs to them
    # so the template can render them directly.
    if choosed_cards:
        for c_card in choosed_cards:
            # Find the matching card in the global deck to get its image path
            matching_card = next((card for card in TAROT_CARDS if card['name'] == c_card['name']), None)
            if matching_card:
                c_card['image'] = matching_card['image']

    deck_copy = [card.copy() for card in TAROT_CARDS]
    shuffled_cards = random.sample(deck_copy, len(deck_copy))

    for card in shuffled_cards:
        card["value"] = random.choice(["invertido", "normal"])

    cards_group1 = shuffled_cards[:7]
    cards_group2 = shuffled_cards[7:15]
    cards_group3 = shuffled_cards[15:]

    return render_template('cartas.html',
                           cards_group1=cards_group1,
                           cards_group2=cards_group2,
                           cards_group3=cards_group3,
                           selected_cards=selected_cards,
                           choosed_cards=choosed_cards)


# Apply a stricter rate limit in production (5/min) to protect the AI API quota.
# In development, the limit is relaxed to 200/min for easy testing.
rate_limit = "5 per minute" if is_production else "200 per minute"

@app.route('/results', methods=['GET', 'POST'])
@limiter.limit(rate_limit)
def results():
    """
    Handles two scenarios for the results page:

    POST — The user has just submitted their chosen cards from /cartas.
            The selected cards are parsed from form data, validated for structure,
            saved to the session (so a page reload doesn't lose them), and the
            results template is rendered.

    GET  — The user reloaded the page or is using a multi-viewport dev tool.
            The saved session data is used to re-render the page without
            requiring re-submission. If there's no session data, the user is
            redirected to /cartas to start over.

    The actual AI reading is NOT generated here — it's triggered client-side
    via a WebSocket event after the page loads (see handle_generation below).
    """

    if request.method == 'POST':
        intencao = session.get('intencao', '')
        selected_cards = session.get('selected_cards', '')
        selected_cards_data = request.form.get('selected_cards_data')

        try:
            choosed_cards = json.loads(selected_cards_data) if selected_cards_data else []

            if not isinstance(choosed_cards, list):
                raise ValueError("Payload root is not a list")

            for card in choosed_cards:
                if not isinstance(card, dict) or 'name' not in card or 'value' not in card:
                    raise ValueError(f"Invalid card structure detected: {card}")

        except (json.JSONDecodeError, ValueError, TypeError) as e:
            logging.warning(f"Card payload rejected: {e} | Raw: {selected_cards_data}")
            choosed_cards = []

        session['choosed_cards'] = choosed_cards
        logging.info(f"Choosed Cards Data (POST): {selected_cards_data}")
        logging.info(f"DEBUG: is_production={is_production}, current limit={rate_limit}")


        # Clear any cached reading from a previous session so a second
        # reading doesn't instantly return the first one from Redis
        # redis_client.delete(f"reading_cache:{request.cookies.get('session')}")
        # redis_client.delete(f"chat_history:{request.cookies.get('session')}")

        return render_template('results.html', intencao=intencao,
                               selected_cards=selected_cards, choosed_cards=choosed_cards)

    else:  # GET request
        choosed_cards = session.get('choosed_cards')
        intencao = session.get('intencao', '')
        selected_cards = session.get('selected_cards', '')

        if not choosed_cards:
            return redirect(url_for('cartas'))

        return render_template('results.html', intencao=intencao,
                               selected_cards=selected_cards, choosed_cards=choosed_cards)
    

@app.errorhandler(404)
def page_not_found(e):
    """
    Catch-all for non-existent routes. 
    Redirects the user back to the Home page instead of showing a 404 error.
    """
    if request.path.startswith('/static/') or request.path.endswith('.ico'):
        return e
    return redirect(url_for('home'))

# =============================================================================
# SOCKET.IO EVENT HANDLERS
# These functions are triggered by events emitted from the browser via WebSocket,
# allowing the server to push data back to the client in real time.
# =============================================================================

@socketio.on('start_generation')
def handle_generation(data):
    """
    Triggered when the results page emits the 'start_generation' event.
    This initiates the AI tarot reading.

    WebSocket connections bypass Flask's standard CSRF middleware, so we
    manually extract and validate the CSRF token from the event payload.
    If valid, the reading is generated and pushed back to the client via
    the 'generation_complete' event.
    """
    csrf_token = data.get('csrf_token')
    if not csrf_token:
        emit('generation_error', {'message': 'CSRF token missing.'})
        return
    try:
        validate_csrf(csrf_token)
    except ValidationError as e:
        emit('generation_error', {'message': str(e)})
        return

    # Capture both IDs while still in request context
    flask_session_id = request.cookies.get('session')
    client_sid = request.sid
    cache_key = f"reading_cache:{flask_session_id}"

    # Return cached reading instantly if it exists (handles reconnects)
    cached = redis_client.get(cache_key)
    if cached:
        logging.info("Returning cached reading to reconnected user.")
        emit('generation_complete', {'reading': cached.decode('utf-8')})
        return

    intencao       = data.get('intencao', '')
    selected_cards = data.get('selected_cards', '')
    choosed_cards  = data.get('choosed_cards', [])

    if not choosed_cards or len(choosed_cards) == 0:
        logging.warning("Generation rejected: choosed_cards array is empty.")
        emit('generation_error', {'message': 'Nenhuma carta foi selecionada. Por favor, recomece a leitura.'})
        return

    def background_generate():
        try:
            reading_html = generate_tarot_reading(intencao, selected_cards, choosed_cards)

            # Write directly to Redis
            redis_client.setex(cache_key, 1800, reading_html)

            socketio.emit('generation_complete', {'reading': reading_html}, to=client_sid)
        except Exception as e:
            logging.error(f"Background generation failed: {e}")
            # Emit a real error instead of a fake reading!
            socketio.emit('generation_error', {'message': 'Não foi possível gerar sua leitura no momento. Tente novamente mais tarde.'}, to=client_sid)

    socketio.start_background_task(background_generate)


@socketio.on('send_message')
def handle_message(data: Dict[str, str]):
    """
    Handles follow-up chat messages from the user after the reading is displayed.

    The entire tarot reading is included in the prompt as context, so the AI
    can give relevant answers to the user's questions. The response is emitted
    back via 'receive_message' for the frontend to display in the chat window.
    """
    # 1. CSRF check
    csrf_token = data.get('csrf_token')
    if not csrf_token:
        # Change to 'generation_error' to trigger the frontend reload UI
        emit('generation_error', {'message': 'Sessão expirada ou token ausente.'})
        return
    try:
        validate_csrf(csrf_token)
    except ValidationError:
        # Change to 'generation_error' to trigger the frontend reload UI
        emit('generation_error', {'message': 'Token de segurança inválido.'})
        return

    # 2. Rate limit check
    # Smart fallback: use session cookie, or IP if cookie is missing
    flask_session_id = request.cookies.get('session') or get_remote_address()
    client_sid = request.sid # Capture the SID
    
    if is_rate_limited(flask_session_id):
        # Use socketio.emit with the specific SID to ensure delivery
        socketio.emit('receive_message', 
                      {'message': 'Você está enviando mensagens muito rapidamente. Aguarde um momento.'}, 
                      to=client_sid)
        return

    # 3. Input validation
    raw_message = data.get('message')
    if not raw_message:
        logging.warning("Chat message rejected: Missing or empty 'message' key.")
        return

    message = sanitize_input(raw_message)

    if len(message) > 500:
        logging.warning(f"Chat message rejected: Exceeded 500 characters. Length: {len(message)}")
        emit('receive_message', {'message': 'Sua mensagem é muito longa. Por favor, resuma sua pergunta em até 500 caracteres.'})
        return

    # 4. Context & History Setup
    tarot_reading = data.get('tarot_reading', '')
    flask_sid = request.cookies.get('session')
    client_sid = request.sid
    history_key = f"chat_history:{flask_sid}"

    # 5. Background AI Task
    def background_chat():
        try:
            raw_history = redis_client.get(history_key)
            history_text = raw_history.decode('utf-8') if raw_history else ""

            chat_prompt = (
                f"Contexto da Leitura:\n{tarot_reading}\n\n"
                f"Histórico da Conversa:\n{history_text}\n"
                f"Usuário: {message}\n"
                f"Tarólogo:"
            )

            response = model.generate_content(chat_prompt)
            ai_response = response.text

            new_history = history_text + f"Usuário: {message}\nTarólogo: {ai_response}\n"
            redis_client.setex(history_key, 1800, new_history)

            socketio.emit('receive_message', {'message': ai_response}, to=client_sid)

        except Exception as e:
            logging.error(f"Error in message generation: {str(e)}")
            socketio.emit('receive_message', {'message': "Ocorreu um erro ao processar sua mensagem."}, to=client_sid)

    socketio.start_background_task(background_chat)

# =============================================================================
# AI READING GENERATION
# =============================================================================

def generate_tarot_reading(intencao: str, selected_cards: str, choosed_cards: List[Dict[str, str]]) -> str:
    """
    Builds a structured prompt from the user's intention, the number of cards
    drawn, and the specific cards (with their orientations), then sends it to
    the Gemma model for a full tarot interpretation.

    The raw Markdown text from the model is converted to HTML before being
    returned, so it renders nicely in the browser.
    """
    prompt = (
        f"Atue como um tarólogo experiente. Faça uma leitura completa de Tarot "
        f"A intenção do usuário é: {intencao}. "
        f"O usuário tirou {selected_cards} cartas. "
        f"As cartas tiradas são: {json.dumps(choosed_cards, ensure_ascii=False)}. "
    )

    response = model.generate_content(prompt)
    
    if not response.text:
        raise ValueError("A API retornou uma resposta vazia.")

    return markdown_to_html(response.text)


# --- Entry Point ---
if __name__ == "__main__":
    # Run with SocketIO instead of Flask's built-in server to support WebSockets.
    # host='0.0.0.0' makes the server accessible from other devices on the network
    # (useful for testing on a phone during development).
    # socketio.run(app, debug=True, host='0.0.0.0', port=5000)

    # Host '0.0.0.0' allows access from external IPs (e.g., phone testing).
    # Debug is only enabled when NOT in production.
    socketio.run(app, debug=not is_production, host='0.0.0.0', port=5000) # nosec


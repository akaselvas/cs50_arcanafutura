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

# Load environment variables
load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    raise ValueError("No SECRET_KEY set for Flask application")

# Check if running on Render (Production)
is_production = os.environ.get('RENDER') is not None

# Enhanced security configurations
app.config.update(
    SECRET_KEY=secret_key,
    SESSION_TYPE='redis',
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,
    
    # FIX: Only require HTTPS cookies in production
    SESSION_COOKIE_SECURE=is_production, 
    # SESSION_COOKIE_SECURE=True,

    SESSION_COOKIE_HTTPONLY=True, # Changed to False to allow javascript to access the token
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='session',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    WTF_CSRF_TIME_LIMIT=1800,
    WTF_CSRF_SSL_STRICT=False,
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_METHODS=['POST', 'PUT', 'PATCH', 'DELETE']  # Explicitly specify methods
)

app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Redis configuration
redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379')
app.config['SESSION_REDIS'] = redis.from_url(redis_url)

# Initialize Redis client
redis_client = redis.Redis.from_url(redis_url)

# Initialize extensions
# csrf = CSRFProtect(app)
# Session(app)
# limiter = Limiter(
#     get_remote_address,
#     app=app,
#     storage_uri=redis_url,
#     storage_options={"socket_connect_timeout": 30},
#     strategy="fixed-window",
#     default_limits=["400 per day", "100 per hour"]
# )

csrf = CSRFProtect(app)
Session(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=redis_url,
    storage_options={"socket_connect_timeout": 30},
    strategy="fixed-window",
    default_limits=["400 per day", "100 per hour"]
)

# CSP in production
# csp={
#     'default-src': "'self'",
#     'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://fonts.gstatic.com"],
#     'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdnjs.cloudflare.com"],
#     'font-src': ["'self'", "https://fonts.googleapis.com", "https://fonts.gstatic.com"],
#     'img-src': ["'self'", "data:"],
#     'connect-src': ["'self'", "wss:", "ws:"]
# }

# csp to browser sync
csp = {
    'default-src': "'self'",
    'style-src': [
        "'self'", 
        "'unsafe-inline'", 
        "https://fonts.googleapis.com", 
        "https://fonts.gstatic.com"
    ],
    'script-src': [
        "'self'", 
        "'unsafe-inline'", 
        "'unsafe-eval'", 
        "https://cdnjs.cloudflare.com", 
        "http://localhost:3000",
        "http://192.168.0.102:3000",
        "https://localhost:*",  # <--- ALLOW RESPONSIVELY APP (HTTPS)
        "http://localhost:*"    # <--- ALLOW RESPONSIVELY APP (HTTP)
    ],
    'font-src': [
        "'self'", 
        "https://fonts.googleapis.com", 
        "https://fonts.gstatic.com"
    ],
    'img-src': ["'self'", "data:", "http://localhost:3000", "http://192.168.0.102:3000"],
    'connect-src': [
        "'self'", 
        "wss:", 
        "ws:", 
        "http://localhost:5000",
        "ws://localhost:5000",
        "http://localhost:3000",
        "ws://localhost:3000",
        "http://192.168.0.102:5000",
        "ws://192.168.0.102:5000",
        "http://192.168.0.102:3000",
        "ws://192.168.0.102:3000",
        "https://localhost:*", # <--- ALLOW RESPONSIVELY APP CONNECTIONS
        "wss://localhost:*"    # <--- ALLOW RESPONSIVELY APP SOCKETS
    ]
}

# Talisman(app)
Talisman(app, content_security_policy=csp)

def sanitize_input(text: str) -> str:
    """Sanitizes user input to prevent XSS attacks."""
    allowed_tags = ['a', 'b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'li', 'ol', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'pre', 'code'] # Example allowed tags – adjust as needed
    allowed_attributes = {'a': ['href', 'rel'], 'img': ['src', 'alt']} # Example allowed attributes – adjust as needed
    cleaned_text = bleach.clean(text, tags=allowed_tags, attributes=allowed_attributes, strip=True)
    return cleaned_text

# Utility functions
def markdown_to_html(text: str) -> Markup:
    return Markup(markdown.markdown(text, extensions=['fenced_code', 'codehilite']))

# CSRF error handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Handle AJAX requests
        return jsonify({
            'error': 'CSRF token validation failed. Please refresh the page.',
            'success': False
        }), 400
    else:
        # Handle regular form submissions
        flash('Security token has expired. Please try again.', 'error')
        return redirect(url_for('home'))
    
    
@app.before_request
def before_request():
    g.nonce = secrets.token_hex(16)
    # REMOVED: Manual session['csrf_token'] assignment. 
    # Flask-WTF handles this automatically when {{ csrf_token() }} is called


# @app.after_request
# def refresh_csrf(response):
#     if 'text/html' in response.headers.get('Content-Type', ''):
#         # Only set the cookie if the token exists in the session
#         if 'csrf_token' in session:
#             response.set_cookie(
#                 'csrf_token',
#                 session['csrf_token'], # <--- FIX: Use the existing token
#                 secure=True,           # Set to True for Render (HTTPS)
#                 httponly=False,
#                 samesite='Lax',
#                 max_age=1800,
#                 domain=None,
#                 path='/'
#             )
#     return response

# Add a new route to check CSRF token status
# @app.route('/check_csrf')
# def check_csrf():
#     csrf_token = session.get('csrf_token')
#     cookie_token = request.cookies.get('csrf_token')
#     return jsonify({
#         'session_token': bool(csrf_token),
#         'cookie_token': bool(cookie_token)
#     })

# API key handling
api_key = os.getenv("GENAI_API_KEY")
if not api_key:
    raise EnvironmentError("Missing GENAI_API_KEY environment variable.")

# Model initialization
genai.configure(api_key=api_key)
generation_config = {
    "temperature": 0.7,
    "top_p": 0.95,
    "top_k": 30,
    "max_output_tokens": 1000,
}
model = genai.GenerativeModel(
    model_name="gemma-3-12b-it",
    generation_config=generation_config
)

# Cache for tarot cards
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

class TarotForm(FlaskForm):
    class Meta:
        csrf = True 

# Routes
@app.route('/')
def home():
    form = TarotForm()  # Create a form instance
    return render_template('index.html', form=form)


# @app.route('/get_csrf')
# def get_csrf():
#     csrf_token = generate_csrf()
#     return jsonify({'csrf_token': csrf_token})

@app.route('/process_form', methods=['POST'])
def process_form():
    form = TarotForm()
    
    # This validate call checks the token against the session automatically
    if not form.validate_on_submit():
        # If validation fails, check specifically for CSRF error to log it
        if form.csrf_token.errors:
            logging.warning(f"CSRF Error: {form.csrf_token.errors}")
            return jsonify({'error': 'Invalid CSRF token'}), 400
        # If other validation fails
        return jsonify({'error': 'Form validation failed'}), 400
        
    intencao = sanitize_input(request.form.get('intencao', '').strip())
    selected_cards = request.form.get('selectedCards')

    if not selected_cards or selected_cards not in ['1', '3', '5']:
        return jsonify({'error': 'Invalid card selection'}), 400

    if len(intencao) > 400:
        return jsonify({'error': 'Intention too long'}), 400

    session['intencao'] = intencao
    session['selected_cards'] = selected_cards

    return jsonify({'redirect': url_for('cartas')})


@app.route('/cartas')
def cartas():
    try:
        selected_cards = int(session.get('selected_cards', 0))
    except (TypeError, ValueError):
        return redirect(url_for('home'))

    # FIX: Create a shallow copy of the dictionaries.
    # This ensures we modify the copy, not the global TAROT_CARDS list.
    deck_copy = [card.copy() for card in TAROT_CARDS] 
    
    shuffled_cards = random.sample(deck_copy, len(deck_copy))
    
    for card in shuffled_cards:
        # Now this modifies the copy, leaving the global TAROT_CARDS clean
        card["value"] = random.choice(["invertido", "normal"])

    cards_group1 = shuffled_cards[:7]
    cards_group2 = shuffled_cards[7:15]
    cards_group3 = shuffled_cards[15:]

    return render_template('cartas.html', 
                           cards_group1=cards_group1, 
                           cards_group2=cards_group2, 
                           cards_group3=cards_group3, 
                           selected_cards=selected_cards)


# @app.route('/results', methods=['POST'])
# @limiter.limit("5 per minute")
# def results():
#     intencao = session.get('intencao', '')
#     selected_cards = session.get('selected_cards', '')
#     selected_cards_data = request.form.get('selected_cards_data')

#     try:
#         choosed_cards = json.loads(selected_cards_data) if selected_cards_data else []
#     except json.JSONDecodeError:
#         choosed_cards = []

#     logging.info(f"Choosed Cards Data: {selected_cards_data}")

#     print(f"Cartas escolhidas: {choosed_cards}")

#     return render_template('results.html', intencao=intencao, selected_cards=selected_cards, choosed_cards=choosed_cards)

rate_limit = "5 per minute" if is_production else "200 per minute"

# 2. Apply it to the route
@app.route('/results', methods=['GET', 'POST'])
@limiter.limit(rate_limit)
def results():
    # --- SCENARIO 1: User submits the form (POST) ---
    if request.method == 'POST':
        intencao = session.get('intencao', '')
        selected_cards = session.get('selected_cards', '')
        selected_cards_data = request.form.get('selected_cards_data')

        try:
            choosed_cards = json.loads(selected_cards_data) if selected_cards_data else []
        except json.JSONDecodeError:
            choosed_cards = []

        # CRITICAL FIX: Save the cards to the session!
        # This allows the page to survive a reload (GET request)
        session['choosed_cards'] = choosed_cards

        logging.info(f"Choosed Cards Data (POST): {selected_cards_data}")
        return render_template('results.html', intencao=intencao, selected_cards=selected_cards, choosed_cards=choosed_cards)

    # --- SCENARIO 2: Page Reload / ResponsivelyApp Sync (GET) ---
    else:
        # Try to recover data from session
        choosed_cards = session.get('choosed_cards')
        intencao = session.get('intencao', '')
        selected_cards = session.get('selected_cards', '')

        # Only redirect if we truly have no data (e.g., user typed url manually)
        if not choosed_cards:
            return redirect(url_for('cartas'))
        
        # Render the page using the saved session data
        return render_template('results.html', intencao=intencao, selected_cards=selected_cards, choosed_cards=choosed_cards)


# SocketIO event handlers
# @socketio.on('start_generation')
# def handle_generation(data: Dict[str, Any]):
#     intencao = data.get('intencao', '')
#     selected_cards = data.get('selected_cards', '')
#     choosed_cards = data.get('choosed_cards', [])

#     reading_html = generate_tarot_reading(intencao, selected_cards, choosed_cards)
#     emit('generation_complete', {'reading': reading_html})

@socketio.on('start_generation')
def handle_generation(data):
    csrf_token = data.get('csrf_token')  # Safely get the csrf_token from the data
    
    if not csrf_token:
        emit('generation_error', {'message': 'CSRF token missing.'}) # Emit an error event
        return

    try:
        validate_csrf(csrf_token) # Validate the token
    except ValidationError as e:  # Catch validation errors
        emit('generation_error', {'message': str(e)}) # Emit an error event
        return
    
    intencao = data.get('intencao', '')
    selected_cards = data.get('selected_cards', '')
    choosed_cards = data.get('choosed_cards', [])
    reading_html = generate_tarot_reading(intencao, selected_cards, choosed_cards)
    
    print(f"CSRF Token: {csrf_token}")  # Now it will only print if csrf_token is defined
    
    emit('generation_complete', {'reading': reading_html})



@socketio.on('send_message')
def handle_message(data: Dict[str, str]):
    message = sanitize_input(data['message'])
    tarot_reading = data.get('tarot_reading', '')

    try:
        chat_prompt = (
            f"Contexto: Uma leitura de tarô foi realizada com o seguinte resultado:\n\n"
            f"{tarot_reading}\n\nIntencao do usuário {message}\n\n"
            f"Por favor, forneça uma resposta com base neste contexto:"
        )
        response = model.generate_content(chat_prompt)  # Assign the value here!
        emit('receive_message', {'message': response.text})
    except Exception as e:
        logging.error(f"Error in message generation: {str(e)}")
        emit('receive_message', {'message': "An error occurred while processing your request. Please try again later."})

def generate_tarot_reading(intencao: str, selected_cards: str, choosed_cards: List[Dict[str, str]]) -> str:
    prompt = (
        f"Atue como um tarólogo experiente. Faça uma leitura completa de Tarot "
        f"A intenção do usuário é: {intencao}. "
        f"O usuário tirou {selected_cards} cartas. "
        f"As cartas tiradas são: {json.dumps(choosed_cards, ensure_ascii=False)}. "
        # f"Foque na interpretação direta e evite textos excessivamente longos."
    )

    try:
        response = model.generate_content(prompt)  # Assign the result of predict() to response
        reading = response.text or "Unable to generate reading." 
    except Exception as e:
        logging.error(f"Error in tarot reading generation: {str(e)}")
        reading = "We're sorry, but we couldn't generate your tarot reading at this time. Please try again later."
    
    return markdown_to_html(reading)

if __name__ == "__main__":
    # Change host to '0.0.0.0' to allow access from external IPs (your phone)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
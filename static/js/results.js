/*
    results.js — Real-Time Reading Generation & Chat Interface

    This script drives the results page, where the AI-generated Tarot
    reading is streamed to the user and a follow-up chat panel lets them
    ask questions about their reading.

    It is split into two functions that are called in sequence:

      initSocket()         — Creates the Socket.IO connection and, once
                             connected, fires startGeneration() to tell
                             the server to begin producing the reading.

      initializeSocket()   — Registers all remaining socket event handlers
                             and wires up the full chat UI. Also called on
                             DOMContentLoaded so the chat panel is ready
                             before the reading arrives.

    High-level flow:
      1. Page loads → DOMContentLoaded fires → initSocket() is called.
      2. Socket connects → server is told to start generating the reading.
      3. Server streams the completed reading back via 'generation_complete'.
      4. The reading is rendered; scroll indicators appear if it overflows.
      5. The user can open the chat panel and ask follow-up questions.
      6. Messages travel over the same socket via 'send_message' /
         'receive_message' events.
*/


// ----------------------------------------------------------------
// MODULE-LEVEL SOCKET REFERENCE
// Declared outside both functions so initSocket() can write it
// and startGeneration() (called from within the connect handler)
// can read it without it being passed as an argument.
// ----------------------------------------------------------------

let socket;


// ----------------------------------------------------------------
// PHASE 1 — CONNECTION SETUP
// Creates the Socket.IO client and registers the minimum set of
// handlers needed to get the generation started as fast as possible.
// The guard `if (!socket)` prevents duplicate connections if
// initSocket() is ever called more than once (e.g. after a hot reload).
// ----------------------------------------------------------------

function initSocket() {
    if (!socket) {
        socket = io({
            /*
                Transport order matters for reliability.
                We start with 'polling' (plain HTTP long-poll) as a
                fallback in case WebSocket upgrades are blocked by a
                proxy or firewall, then upgrade to 'websocket' once
                the connection is established.
            */
            transports: ['polling', 'websocket'],
            forceNew: true  // Always open a fresh connection, never reuse a stale one.
        });

        socket.on('connect', function() {
            console.log('Socket connected');
            startGeneration(); // Kick off generation immediately on connect.
        });

        socket.on('connect_error', function(error) {
            // Logged for debugging; a production version might show a
            // user-facing retry prompt here.
            console.error('Connection error:', error);
        });

        // --------------------------------------------------------
        // READING DELIVERY
        // The server emits 'generation_complete' with the finished
        // reading HTML once the AI has produced the full text.
        // We hide the loading spinner and inject the reading into
        // the result container.
        // --------------------------------------------------------
        socket.on('generation_complete', function(data) {
            document.getElementById('loading-message').style.display = 'none';
            document.getElementById('result-area').style.display = 'block';
            document.getElementById('tarot-reading').innerHTML = data.reading;
        });

        // --------------------------------------------------------
        // GENERATION ERROR
        // If the server-side AI call fails, the server emits this
        // event instead of 'generation_complete'. We surface a
        // plain-language message rather than a raw error code.
        // --------------------------------------------------------
        socket.on('generation_error', function(data) {
            console.error('Generation error:', data);
            document.getElementById('loading-message').style.display = 'none';
            document.getElementById('tarot-reading').innerHTML =
                'An error occurred while generating your reading. Please try again.';
            document.getElementById('result-area').style.display = 'block';
        });
    }
}


// ----------------------------------------------------------------
// PHASE 1 — TRIGGER GENERATION
// Reads the user's session data from hidden <input> fields rendered
// by Flask/Jinja2 and emits them to the server so it can pass them
// to the AI model.
//
// The choosedCards field is wrapped in a try/catch because it is
// a JSON string that was serialised server-side. If something went
// wrong during that serialisation (empty string, malformed JSON),
// we fall back to an empty array rather than crashing the whole page.
// ----------------------------------------------------------------

function startGeneration() {
    const intencao     = document.getElementById('intencaoData').value;
    const selectedCards = document.getElementById('selectedCardsData').value;
    let choosedCards   = [];

    try {
        const choosedCardsData = document.getElementById('choosedCardsData').value;
        if (choosedCardsData && choosedCardsData.trim() !== '') {
            choosedCards = JSON.parse(choosedCardsData);
        }
    } catch (error) {
        console.error('Error parsing choosed cards:', error);
    }

    console.log('Sending data:', { intencao, selected_cards: selectedCards, choosed_cards: choosedCards });

    // Emit the reading request; the server listens for 'start_generation'
    // and begins the AI streaming pipeline.
    socket.emit('start_generation', {
        intencao:      intencao,
        selected_cards: selectedCards,
        choosed_cards: choosedCards,
    });
}


// ----------------------------------------------------------------
// PHASE 2 — FULL UI SETUP
// Called on DOMContentLoaded alongside initSocket(). Sets up:
//   • Scroll overflow detection and visual indicators.
//   • The slide-in chat panel and its open/close buttons.
//   • Message sending (button click and Enter key).
//   • Incoming message rendering with Markdown support.
// ----------------------------------------------------------------

function initializeSocket() {

    socket = io({ transports: ['websocket'] });


    // ----------------------------------------------------------------
    // DOM ELEMENT REFERENCES
    // All elements are looked up once here. Grouping them together at
    // the top of the function makes it easy to see the full surface
    // area this script touches without hunting through the code below.
    // ----------------------------------------------------------------

    const contentWrapper   = document.getElementById('content-wrapper');
    const resultArea       = document.getElementById('result-area');
    const shadowOverlay    = document.getElementById('shadow-overlay');    // Gradient fade at the bottom of long readings.
    const scrollIndicator  = document.getElementById('scroll-indicator'); // "Scroll down" arrow / prompt.
    const chatInterface    = document.getElementById('chat-interface');
    const chatOverlay      = document.getElementById('chat-overlay');     // Semi-transparent backdrop behind the chat panel.
    const openChatButton   = document.getElementById('open-chat');
    const closeChatButton  = document.getElementById('close-chat');
    const chatMessages     = document.getElementById('chat-messages');    // Scrollable message history container.
    const userInput        = document.getElementById('user-input');
    const sendMessageButton = document.getElementById('send-message');

    let tarotReading    = ''; // Stores the full reading text so it can be sent as context with each chat message.
    let isFirstChatOpen = true; // Tracks whether the bot's greeting has been shown yet.


    // ----------------------------------------------------------------
    // READING DELIVERY (PHASE 2 HANDLER)
    // A second 'generation_complete' handler that runs after the UI
    // is fully set up. It stores the reading text for the chat context
    // and then checks whether the reading overflows its container
    // (triggering scroll indicators if needed).
    //
    // The 40 000 ms delay on checkContentOverflow is intentional:
    // it waits for any CSS reveal animations on the reading text to
    // fully complete before measuring element heights, which would
    // otherwise return incorrect values mid-animation.
    // ----------------------------------------------------------------

    socket.on('generation_complete', function(data) {
        document.getElementById('loading-message').style.display = 'none';
        resultArea.style.display = 'block';
        document.getElementById('tarot-reading').innerHTML = data.reading;
        tarotReading = data.reading;

        setTimeout(checkContentOverflow, 40000);
    });


    // ----------------------------------------------------------------
    // SCROLL OVERFLOW DETECTION
    // Long readings may exceed the visible area of contentWrapper.
    // We compare the reading's natural scrollHeight against the
    // wrapper's visible clientHeight to decide whether to show the
    // "scroll down" hint.
    // ----------------------------------------------------------------

    function checkContentOverflow() {
        if (resultArea.scrollHeight > contentWrapper.clientHeight) {
            showScrollIndicators();
        } else {
            hideScrollIndicators();
        }
    }

    function showScrollIndicators() {
        shadowOverlay.style.display   = 'block';
        scrollIndicator.style.display = 'block';
    }

    function hideScrollIndicators() {
        shadowOverlay.style.display   = 'none';
        scrollIndicator.style.display = 'none';
    }

    // Returns true when the user has scrolled to within 5 px of the
    // bottom — a small tolerance to account for sub-pixel rounding.
    function isAtBottom() {
        const scrollTop    = contentWrapper.scrollTop;
        const scrollHeight = contentWrapper.scrollHeight;
        const clientHeight = contentWrapper.clientHeight;
        const tolerance    = 5; // pixels

        return scrollTop + clientHeight >= scrollHeight - tolerance;
    }

    // Hide the indicators once the user has scrolled to the bottom;
    // re-show them if they scroll back up and content still overflows.
    contentWrapper.addEventListener('scroll', function() {
        if (isAtBottom()) {
            hideScrollIndicators();
        } else if (resultArea.scrollHeight > contentWrapper.clientHeight) {
            showScrollIndicators();
        }
    });

    // Re-check on resize because a viewport change can make previously
    // non-overflowing content start overflowing (or vice versa).
    window.addEventListener('resize', checkContentOverflow);


    // ----------------------------------------------------------------
    // CHAT PANEL — OPEN / CLOSE
    // The panel slides in over the reading. On the first open we
    // inject a greeting message from the bot so the conversation
    // feels alive immediately. The flag ensures the greeting only
    // appears once per session, not every time the panel is reopened.
    // ----------------------------------------------------------------

    openChatButton.addEventListener('click', () => {
        chatInterface.style.display = 'flex';
        chatOverlay.style.display   = 'block';

        if (isFirstChatOpen) {
            addMessage('bot', 'Olá, vamos conversar mais sobre sua leitura, o que você quer saber?');
            isFirstChatOpen = false;
        }
    });

    closeChatButton.addEventListener('click', () => {
        chatInterface.style.display = 'none';
        chatOverlay.style.display   = 'none';
    });


    // ----------------------------------------------------------------
    // CHAT — SEND MESSAGE
    // Triggered by button click or the Enter key. Both paths call the
    // same sendMessage() function to keep the logic in one place.
    // ----------------------------------------------------------------

    sendMessageButton.addEventListener('click', sendMessage);

    userInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    function sendMessage() {
        const message = userInput.value.trim();

        if (message) {
            addMessage('user', message);
            showLoadingIndicator(); // Show typing dots while waiting for the bot reply.

            /*
                The full tarotReading text is sent alongside the user's
                message so the server can pass it as context to the AI
                model. Without it, the AI would have no memory of what
                was in the reading and couldn't give meaningful follow-up answers.
            */
            socket.emit('send_message', { message: message, tarot_reading: tarotReading });
            userInput.value = '';
        }
    }

    // Render the bot's reply once the server emits it.
    socket.on('receive_message', (data) => {
        removeLoadingIndicator();
        addMessage('bot', data.message);
    });


    // ----------------------------------------------------------------
    // CHAT — LOADING INDICATOR
    // An animated "..." bubble is appended while the bot is thinking.
    // removeLoadingIndicator() finds it by checking for the
    // '.loading-dots' class on the last message, so it reliably removes
    // only the placeholder and not a real message.
    // ----------------------------------------------------------------

    function showLoadingIndicator() {
        const loadingDiv = document.createElement('div');
        loadingDiv.classList.add('chat-message', 'bot-message');
        loadingDiv.innerHTML = `
            <div class="chat-message-content">
                <span class="loading-dots">
                    .<span>.</span><span>.</span><span>.</span>
                </span>
            </div>
        `;
        chatMessages.appendChild(loadingDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight; // Keep the new bubble in view.
    }

    function removeLoadingIndicator() {
        const lastMessage = chatMessages.querySelector('.chat-message:last-child');
        if (lastMessage && lastMessage.querySelector('.loading-dots')) {
            lastMessage.remove();
        }
    }


    // ----------------------------------------------------------------
    // CHAT — MESSAGE RENDERING
    // Bot messages are parsed through the `marked` library (a Markdown
    // renderer) if it is available. This lets the AI model use bold,
    // italics, and lists in its replies without the raw symbols showing.
    // User messages are inserted as plain text to avoid any XSS risk
    // from user-supplied content being interpreted as HTML.
    // ----------------------------------------------------------------

    function addMessage(sender, content) {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add(
            'chat-message',
            sender === 'user' ? 'user-message' : 'bot-message'
        );

        // Only parse Markdown for bot messages, and only if the
        // `marked` library was successfully loaded on the page.
        if (sender === 'bot' && typeof marked !== 'undefined') {
            content = marked.parse(content);
        }

        messageDiv.innerHTML = `<div class="chat-message-content">${content}</div>`;
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight; // Auto-scroll to latest message.
    }

    // Expose startGeneration on the window object so it can be called
    // from inline scripts or other modules if needed.
    window.startGeneration = startGeneration;

}


/*
    ENTRY POINT
    initSocket() is all that needs to be called on load — it creates the
    connection and fires startGeneration() once the socket is ready.

    The commented-out block below was an earlier version that called both
    functions manually and passed data as arguments. It was replaced by
    the current approach where startGeneration() reads the hidden inputs
    directly, removing the need to pass data through function parameters.
*/

// document.addEventListener('DOMContentLoaded', function () {
//     const intencao = document.getElementById('intencaoData').value;
//     const selectedCards = document.getElementById('selectedCardsData').value;
//     const choosedCards = JSON.parse(document.getElementById('choosedCardsData').value);
//
//     initSocket();
//     startGeneration(intencao, selectedCards, choosedCards);
// });

document.addEventListener('DOMContentLoaded', initSocket);

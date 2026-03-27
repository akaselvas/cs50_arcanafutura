/*
    cartas.js — Card Selection & Submission Logic

    This script powers the interactive card-picking screen.
    After the user selects how many cards they want on the home page,
    they land here and must physically "flip" that many cards from a
    shuffled deck.  Once all required cards are chosen, a confirmation
    button appears and the selection is submitted to the server for the
    AI-generated reading.

    High-level flow:
      1. The user clicks a face-down card  → it animates and flips.
      2. The flip repeats until clickedCards === selectedCardsCount.
      3. A "ver leitura" button appears; the remaining cards are disabled.
      4. On button click, the chosen cards are POSTed to /cartas via fetch().
      5. On success, a hidden <form> is dynamically built and submitted to
         the results page so the data survives the navigation.
*/

document.addEventListener('DOMContentLoaded', function () {

    // ----------------------------------------------------------------
    // ELEMENT & STATE REFERENCES
    // All DOM lookups happen once at startup and are stored in constants
    // so we don't re-query the DOM on every click.
    // ----------------------------------------------------------------

    const cards             = document.querySelectorAll('.card');
    const containerBotoes   = document.querySelector('.container-botoes-cartas');
    const leituraButton     = document.querySelector('.botao-texto-grande');

    /*
        selectedCardsCount is written into the HTML as a hidden <input>
        by Flask (value = 1, 3, or 5) so this script doesn't need to
        know about the session — it just reads the rendered value.
        parseInt() converts the string attribute to a real number so
        comparison with clickedCards (a counter) works correctly.
    */
    const selectedCardsCount = parseInt(document.getElementById('selectedCardsCount').value);

    let clickedCards      = 0;   // How many cards the user has flipped so far.
    let selectedCardsData = [];  // Accumulates { name, value } objects for each flipped card.


    // ----------------------------------------------------------------
    // CARD FLIP INTERACTION
    // Each card in the deck gets the same click listener.
    // Cards store their face image, display name, and orientation
    // (upright / invertido) as data-* attributes set by Flask/Jinja2.
    // ----------------------------------------------------------------

    cards.forEach(card => {
        card.addEventListener('click', () => {

            /*
                Early-exit guard: ignore clicks on cards that have
                already been flipped ('clicked' class) or when the user
                has already chosen the required number of cards.
                This prevents selecting more cards than allowed and
                avoids re-triggering the flip animation.
            */
            if (card.classList.contains('clicked') || clickedCards >= selectedCardsCount) {
                return;
            }

            // Read the card's metadata from its HTML data attributes.
            const imageUrl  = card.getAttribute('data-image'); // Path to the card face image.
            const cardName  = card.getAttribute('data-name');  // Human-readable card title.
            const cardValue = card.getAttribute('data-value'); // 'normal' or 'invertido'.

            // --------------------------------------------------------
            // FLIP ANIMATION
            // We use a CSS transform instead of a CSS class toggle so
            // we can control the exact duration from JavaScript and
            // synchronise the image swap to the midpoint of the flip.
            //
            // Two different rotations are used to visually distinguish
            // upright cards (Y-axis flip, like turning a page) from
            // reversed cards (X-axis flip, like tumbling forward),
            // reinforcing the Tarot concept of card orientation.
            // --------------------------------------------------------

            const animationDuration = 1000; // ms — total flip duration.

            card.style.transition = `transform ${animationDuration}ms ease`;

            if (cardValue === 'invertido') {
                card.style.transform = "rotateX(180deg)"; // Reversed: tumble forward.
            } else {
                card.style.transform = "rotateY(180deg)"; // Upright: standard page-turn flip.
            }

            /*
                IMAGE SWAP AT MIDPOINT
                We wait until 1/3 of the animation has elapsed — roughly
                when the card is edge-on and invisible to the user — then
                switch the background to the face image. This creates the
                illusion that the card physically turned over to reveal
                its face, rather than an abrupt swap on an already-visible card.
            */
            setTimeout(() => {

                card.style.backgroundImage = `url(${imageUrl})`;
                card.classList.add('clicked'); // Marks this card as already flipped.
                clickedCards++;
                selectedCardsData.push({ name: cardName, value: cardValue });

                /*
                    COMPLETION CHECK
                    Once the user has flipped all required cards, reveal
                    the "ver leitura" confirmation button and lock the rest
                    of the deck so no extra cards can be accidentally chosen.
                */
                if (clickedCards === selectedCardsCount) {
                    containerBotoes.style.display = 'block';
                    disableUnselectedCards();
                }

            }, animationDuration / 3); // Fire at ~333 ms into a 1000 ms flip.
        });
    });


    // ----------------------------------------------------------------
    // DISABLE UNCHOSEN CARDS
    // Called once the selection is complete. Adds a 'disabled' CSS class
    // to every card that wasn't picked so they appear greyed-out and
    // no longer respond to pointer events (controlled via CSS).
    // We do NOT use the HTML disabled attribute here because <div> / <li>
    // elements don't support it — the class is our own visual convention.
    // ----------------------------------------------------------------

    function disableUnselectedCards() {
        cards.forEach(card => {
            if (!card.classList.contains('clicked')) {
                card.classList.add('disabled');
            }
        });
    }


    // ----------------------------------------------------------------
    // CONFIRMATION BUTTON HANDLER
    // Intercepts the default click so we can run our async fetch first.
    // ----------------------------------------------------------------

    leituraButton.addEventListener('click', function (e) {
        e.preventDefault(); // Prevent any default navigation or form submit.
        submitChosenCards(selectedCardsData);
    });


    // ----------------------------------------------------------------
    // ASYNC SUBMISSION & RESULTS NAVIGATION
    //
    // Two-step process:
    //   Step 1 — POST the chosen cards to /cartas via fetch() with a
    //             JSON body. The server validates the selection and
    //             returns { success: true } or an error.
    //   Step 2 — On success, dynamically construct a hidden <form> and
    //             programmatically submit it to the results URL.
    //
    // Why two steps instead of one fetch to the results page?
    //   • fetch() can't trigger a true browser navigation on its own.
    //   • A standard form POST sends the correct Content-Type and lets
    //     Flask render a full HTML page in response (the reading page).
    //   • The hidden form approach bridges the gap: fetch() confirms
    //     the data is valid, then the form POST delivers it properly.
    // ----------------------------------------------------------------

    function submitChosenCards(chosenCards) {

        // Write the selection into the hidden input for any legacy
        // server-side reads that inspect the raw form field.
        document.getElementById('choosedCards').value = JSON.stringify(chosenCards);

        fetch('/cartas', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                /*
                    CSRF protection for JSON requests.
                    Flask-WTF's default CSRF validation checks the
                    'X-CSRFToken' header when the request body is JSON
                    (not a multipart form), so we send the token here
                    rather than inside the JSON body.
                */
                'X-CSRFToken': document.getElementById('csrfToken').value
            },
            body: JSON.stringify({ choosed_cards: chosenCards })
        })
        .then(response => response.json())
        .then(data => {

            if (data.success) {

                /*
                    BUILD AND SUBMIT THE RESULTS FORM
                    We create a temporary <form> in memory, populate it
                    with three hidden fields, attach it to the DOM just
                    long enough to call .submit(), then the browser
                    navigates away naturally.

                    Fields sent:
                      • choosed_cards      — the raw array of chosen cards (JSON string).
                      • selected_cards_data — same data, kept for potential
                                             server-side use under a different key.
                      • csrf_token         — required by Flask-WTF for every POST,
                                             even programmatic ones.
                */

                const form    = document.createElement('form');
                form.method   = 'POST';
                form.action   = document.getElementById('resultsUrl').value;

                // Field 1: chosen cards data.
                const choosedCardsInput   = document.createElement('input');
                choosedCardsInput.type    = 'hidden';
                choosedCardsInput.name    = 'choosed_cards';
                choosedCardsInput.value   = JSON.stringify(chosenCards);
                form.appendChild(choosedCardsInput);

                // Field 2: same data under the alternate key the results
                // route may also read from.
                const dataInput   = document.createElement('input');
                dataInput.type    = 'hidden';
                dataInput.name    = 'selected_cards_data';
                dataInput.value   = JSON.stringify(selectedCardsData);
                form.appendChild(dataInput);

                // Field 3: CSRF token — the results route is also a POST
                // endpoint protected by Flask-WTF.
                const csrfInput   = document.createElement('input');
                csrfInput.type    = 'hidden';
                csrfInput.name    = 'csrf_token';
                csrfInput.value   = document.getElementById('csrfToken').value;
                form.appendChild(csrfInput);

                // Attach, submit, and let the browser take over navigation.
                document.body.appendChild(form);
                form.submit();

            } else {
                // The server accepted the request but flagged a logical
                // error (e.g. invalid card names). Log for debugging;
                // a more polished version might show a user-facing message.
                console.error('Error submitting chosen cards');
            }
        })
        .catch(error => console.error('Error:', error));
        // .catch handles network-level failures (offline, server down, etc.)
    }

});
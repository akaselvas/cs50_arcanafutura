/*
    card-selection.js — Card Count Button Selection & Form Guard

    This script handles the card-count selector on the home page (1, 3, or 5 cards)
    and adds a client-side validation guard to the form submission.

    High-level flow:
      1. The user clicks one of the three count buttons (1, 3, or 5).
      2. All buttons are dimmed and the clicked one is highlighted as the
         active selection.
      3. The chosen value is written into a hidden form field so the server
         receives it as a standard POST parameter.
      4. On form submit, a guard checks that a value was actually selected
         and blocks submission with an alert if not.
*/

document.addEventListener('DOMContentLoaded', function() {

    // ----------------------------------------------------------------
    // ELEMENT REFERENCES
    // Queried once at startup and stored in constants to avoid
    // redundant DOM lookups on every button click.
    // ----------------------------------------------------------------

    const botoes             = document.querySelectorAll('.botao-personalizado'); // All three count buttons (1, 3, 5).
    const selectedCardsInput = document.getElementById('selectedCards');          // Hidden input that carries the value to the server.


    // ----------------------------------------------------------------
    // CARD COUNT BUTTON SELECTION
    // Only one button can be active at a time. When the user clicks one:
    //   1. Every button is reset to its inactive state (dimmed, disabled).
    //   2. The clicked button is re-enabled and highlighted as selected.
    //   3. Its data-value (1, 3, or 5) is written to the hidden input
    //      so the form submission includes it as a named field.
    //
    // Buttons are disabled after selection (not just dimmed) to prevent
    // the user from changing their mind mid-flow, keeping the UX deliberate
    // and in line with the ritual atmosphere of a Tarot reading.
    // The clicked button itself is re-enabled so it remains visually
    // interactive and doesn't appear broken to the user.
    // ----------------------------------------------------------------

    botoes.forEach(botao => {
        botao.addEventListener('click', () => {

            // Reset all buttons to their inactive state first.
            botoes.forEach(b => {
                b.classList.remove('active');
                b.style.opacity = '0.5';
                b.disabled = true;
            });

            // Highlight the chosen button and re-enable it so it
            // doesn't render in the browser's greyed-out disabled style.
            botao.classList.add('active');
            botao.style.opacity = '1';
            botao.disabled = false;

            // Write the card count into the hidden field so the server
            // receives it as a standard POST parameter on form submit.
            selectedCardsInput.value = botao.dataset.value;
        });
    });


    // ----------------------------------------------------------------
    // FORM SUBMISSION GUARD
    // A lightweight client-side check that runs before the form is sent.
    // If the user somehow reaches the submit button without picking a
    // card count (e.g. by pressing Enter in the textarea), we block the
    // submission and prompt them to make a selection first.
    //
    // Note: this is a UX convenience only — the server validates the
    // selectedCards field independently and will reject an empty value
    // regardless of what happens here.
    // ----------------------------------------------------------------

    document.getElementById('tarotForm').addEventListener('submit', function (e) {
        if (!selectedCardsInput.value) {
            e.preventDefault(); // Stop the form from POSTing with an empty card count.
            alert('Por favor, selecione o número de cartas antes de continuar.');
        }
    });

});
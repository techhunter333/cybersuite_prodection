document.addEventListener('DOMContentLoaded', function () {
    const inputTextElem = document.getElementById('input-text');
    const outputTextElem = document.getElementById('output-text');
    const cipherTypeElem = document.getElementById('cipher-type');
    const operationTypeElem = document.getElementById('operation-type');
    const processBtn = document.getElementById('process-btn');
    const swapBtn = document.getElementById('swap-btn');
    const copyOutputBtn = document.getElementById('copy-output-btn');
    const errorMessageElem = document.getElementById('error-message');

    // Caesar options
    const caesarOptionsElem = document.getElementById('caesar-options');
    const caesarShiftElem = document.getElementById('caesar-shift');

    // Substitution options
    const substitutionOptionsElem = document.getElementById('substitution-options');
    const substitutionKeyElem = document.getElementById('substitution-key');
    const generateRandomSubKeyBtn = document.getElementById('generate-random-sub-key');

    const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    // --- [CRITICAL SECURITY FIX] SECURE RANDOMNESS FUNCTION ---
    function getSecureRandomIndex(max) {
        if (typeof window.crypto.getRandomValues !== 'function') {
            // Fallback for extremely old browsers, though most modern ones support it
            return Math.floor(Math.random() * max); 
        }
        const randomValues = new Uint32Array(1);
        window.crypto.getRandomValues(randomValues);
        return randomValues[0] % max;
    }
    // --- END SECURE RANDOMNESS ---

    function showError(message) {
        errorMessageElem.textContent = message;
        errorMessageElem.style.display = 'block';
        outputTextElem.value = '';
        copyOutputBtn.style.display = 'none';
    }

    function hideError() {
        errorMessageElem.style.display = 'none';
        errorMessageElem.textContent = '';
    }

    function toggleCipherOptions() {
        if (cipherTypeElem.value === 'caesar') {
            caesarOptionsElem.style.display = 'block';
            substitutionOptionsElem.style.display = 'none';
        } else if (cipherTypeElem.value === 'substitution') {
            caesarOptionsElem.style.display = 'none';
            substitutionOptionsElem.style.display = 'block';
        }
    }

    function caesarCipher(text, shift, encrypt) {
        let result = '';
        shift = parseInt(shift);
        if (isNaN(shift)) {
            showError("Caesar shift key must be a number.");
            return '';
        }

        shift = encrypt ? shift : (26 - shift); 

        for (let i = 0; i < text.length; i++) {
            let char = text[i];
            if (char.match(/[a-z]/i)) { 
                let code = text.charCodeAt(i);
                let base;
                if (code >= 65 && code <= 90) { // Uppercase A-Z
                    base = 65;
                } else if (code >= 97 && code <= 122) { // Lowercase a-z
                    base = 97;
                }
                char = String.fromCharCode(((code - base + shift) % 26) + base);
            }
            result += char;
        }
        return result;
    }

    function substitutionCipher(text, key, encrypt) {
        key = key.toUpperCase();
        if (key.length !== 26 || new Set(key).size !== 26 || !/^[A-Z]+$/.test(key)) {
            showError("Substitution key must be 26 unique uppercase letters (A-Z).");
            return '';
        }

        let result = '';
        const fromAlphabet = encrypt ? ALPHABET : key;
        const toAlphabet = encrypt ? key : ALPHABET;

        for (let i = 0; i < text.length; i++) {
            let char = text[i];
            const isUpperCase = char === char.toUpperCase();
            const charUpper = char.toUpperCase();
            const index = fromAlphabet.indexOf(charUpper);

            if (index !== -1) { 
                let substitutedChar = toAlphabet[index];
                result += isUpperCase ? substitutedChar : substitutedChar.toLowerCase();
            } else {
                result += char; 
            }
        }
        return result;
    }
    
    // --- [FIXED] Uses secure random index for shuffle ---
    function generateRandomSubstitutionKey() {
        let alphabetArray = ALPHABET.split('');
        // Fisher-Yates (Knuth) Shuffle
        for (let i = alphabetArray.length - 1; i > 0; i--) {
            // Use secure random index for the swap
            const j = getSecureRandomIndex(i + 1); 
            [alphabetArray[i], alphabetArray[j]] = [alphabetArray[j], alphabetArray[i]];
        }
        substitutionKeyElem.value = alphabetArray.join('');
    }
    // --- END FIXED FUNCTION ---


    function processText() {
        hideError();
        const inputText = inputTextElem.value;
        const cipherType = cipherTypeElem.value;
        const operation = operationTypeElem.value === 'encrypt'; 
        let outputText = '';

        if (!inputText.trim()) {
            showError("Input text cannot be empty.");
            return;
        }

        if (cipherType === 'caesar') {
            const shift = caesarShiftElem.value;
            outputText = caesarCipher(inputText, shift, operation);
        } else if (cipherType === 'substitution') {
            const key = substitutionKeyElem.value;
            outputText = substitutionCipher(inputText, key, operation);
        }

        outputTextElem.value = outputText;
        copyOutputBtn.style.display = outputText ? 'block' : 'none';
    }

    function swapTexts() {
        hideError();
        const temp = inputTextElem.value;
        inputTextElem.value = outputTextElem.value;
        outputTextElem.value = temp;
        copyOutputBtn.style.display = outputTextElem.value ? 'block' : 'none';
    }
    
    function copyOutputToClipboard() {
        if (!outputTextElem.value) return;
        outputTextElem.select();
        outputTextElem.setSelectionRange(0, 99999);

        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(outputTextElem.value).then(() => {
                    copyOutputBtn.textContent = 'Copied!';
                    setTimeout(() => { copyOutputBtn.textContent = 'Copy'; }, 1500);
                }).catch(err => {
                    console.warn('Async clipboard copy failed:', err);
                    legacyCopy();
                });
            } else {
                legacyCopy();
            }
        } catch (err) {
             alert('Failed to copy. Please copy manually.');
        }
    }

    function legacyCopy() {
        try {
            const successful = document.execCommand('copy');
            if (successful) {
                copyOutputBtn.textContent = 'Copied!';
                setTimeout(() => { copyOutputBtn.textContent = 'Copy'; }, 1500);
            } else {
                throw new Error('Legacy copy failed.');
            }
        } catch(err) {
            alert('Failed to copy using legacy method. Please copy manually.');
        }
    }


    // Event Listeners
    cipherTypeElem.addEventListener('change', toggleCipherOptions);
    processBtn.addEventListener('click', processText);
    swapBtn.addEventListener('click', swapTexts);
    copyOutputBtn.addEventListener('click', copyOutputToClipboard);
    if (generateRandomSubKeyBtn) {
        generateRandomSubKeyBtn.addEventListener('click', generateRandomSubstitutionKey);
    }


    // Initial setup
    toggleCipherOptions();
});
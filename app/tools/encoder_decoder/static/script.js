document.addEventListener('DOMContentLoaded', function () {
    console.log("Encoder/Decoder Script Loaded (Client-Side Optimized).");

    // --- DOM Elements ---
    const inputTextElem = document.getElementById('input-text');
    const outputTextElem = document.getElementById('output-text');
    
    const operationTypeElem = document.getElementById('operation-type');
    const encodingFormatElem = document.getElementById('encoding-format');
    
    const processBtn = document.getElementById('process-btn');
    const swapBtn = document.getElementById('swap-btn');
    const clearBtn = document.getElementById('clear-btn');
    const copyOutputBtn = document.getElementById('copy-output-btn');
    
    const errorMessageElem = document.getElementById('error-message');

    // --- Helper Functions ---

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

    // --- Encoding/Decoding Logic ---

    // 1. Base64 (UTF-8 Safe & Large Input Safe)
    function processBase64(text, isDecode) {
        if (isDecode) {
            try {
                // Clean input (remove whitespace often found in base64 blocks)
                const cleanText = text.replace(/\s/g, '');
                
                // Decode Base64 -> Binary String -> Uint8Array -> UTF-8 String
                const binaryString = window.atob(cleanText);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                return new TextDecoder().decode(bytes);
            } catch (e) {
                throw new Error("Invalid Base64 string. Ensure the input is correct.");
            }
        } else {
            // Encode UTF-8 String -> Uint8Array -> Binary String -> Base64
            const bytes = new TextEncoder().encode(text);
            
            // OPTIMIZATION: Handle large strings to avoid "Maximum call stack size exceeded"
            let binaryString = '';
            const chunkSize = 0x8000; // 32KB chunks
            for (let i = 0; i < bytes.length; i += chunkSize) {
                binaryString += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
            }
            
            return window.btoa(binaryString);
        }
    }

    // 2. URL Encoding
    function processURL(text, isDecode) {
        if (isDecode) {
            try {
                return decodeURIComponent(text);
            } catch (e) {
                throw new Error("Invalid URL encoded text (Malformed URI sequence).");
            }
        } else {
            // encodeURIComponent handles UTF-8 natively
            return encodeURIComponent(text);
        }
    }

    // 3. Hexadecimal
    function processHex(text, isDecode) {
        if (isDecode) {
            // IMPROVEMENT: Clean input by removing spaces, newlines, tabs
            // This allows users to paste formatted hex like "48 65 6c 6c 6f"
            const cleanHex = text.replace(/[\s\n\r]/g, '');
            
            if (cleanHex.length % 2 !== 0) {
                throw new Error("Invalid Hex: Length must be even.");
            }
            if (!/^[0-9A-Fa-f]*$/.test(cleanHex)) {
                throw new Error("Invalid Hex: Contains non-hexadecimal characters.");
            }

            const bytes = new Uint8Array(cleanHex.length / 2);
            for (let i = 0; i < cleanHex.length; i += 2) {
                bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
            }
            return new TextDecoder().decode(bytes);
        } else {
            const bytes = new TextEncoder().encode(text);
            return Array.from(bytes)
                .map(b => b.toString(16).padStart(2, '0'))
                .join(''); // Compact output
        }
    }

    // --- Main Process Handler ---

    function processText() {
        hideError();
        const inputText = inputTextElem.value;
        const operation = operationTypeElem.value;
        const format = encodingFormatElem.value;
        const isDecode = (operation === 'decode');
        let outputText = '';

        // Logic: Encode requires input. Decode allows empty input (returns empty).
        if (!inputText && !isDecode) {
            showError('Input text cannot be empty for encoding.');
            return;
        }
        if (!inputText && isDecode) {
            outputTextElem.value = '';
            return;
        }

        try {
            switch (format) {
                case 'base64':
                    outputText = processBase64(inputText, isDecode);
                    break;
                case 'url':
                    outputText = processURL(inputText, isDecode);
                    break;
                case 'hex':
                    outputText = processHex(inputText, isDecode);
                    break;
                default:
                    throw new Error("Unknown format selected.");
            }

            outputTextElem.value = outputText;
            copyOutputBtn.style.display = outputText ? 'inline-block' : 'none';

        } catch (error) {
            console.error("Processing Error:", error);
            showError(error.message || "An error occurred during processing.");
        }
    }

    // --- Utilities ---

    function swapTexts() {
        const currentOutput = outputTextElem.value;
        if (currentOutput) {
            inputTextElem.value = currentOutput;
            outputTextElem.value = '';
            hideError();
            copyOutputBtn.style.display = 'none';
            
            // Smart toggle: switch operation mode automatically
            operationTypeElem.value = (operationTypeElem.value === 'encode') ? 'decode' : 'encode';
        }
    }

    function clearAll() {
        hideError();
        inputTextElem.value = '';
        outputTextElem.value = '';
        copyOutputBtn.style.display = 'none';
        inputTextElem.focus();
    }

    function copyOutputToClipboard() {
        if (!outputTextElem.value) return;
        outputTextElem.select();
        outputTextElem.setSelectionRange(0, 99999); // For mobile

        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(outputTextElem.value).then(() => {
                    const original = copyOutputBtn.textContent;
                    copyOutputBtn.textContent = 'Copied!';
                    setTimeout(() => { copyOutputBtn.textContent = original; }, 1500);
                }).catch(err => {
                    console.warn('Async copy failed, trying legacy:', err);
                    legacyCopy();
                });
            } else {
                legacyCopy();
            }
        } catch (err) {
            alert('Failed to copy text. Please copy manually.');
        }
    }

    function legacyCopy() {
        try {
            const successful = document.execCommand('copy');
            if (successful) {
                const original = copyOutputBtn.textContent;
                copyOutputBtn.textContent = 'Copied!';
                setTimeout(() => { copyOutputBtn.textContent = original; }, 1500);
            } else {
                throw new Error('Copy command failed');
            }
        } catch (err) {
            alert('Failed to copy text.');
        }
    }

    // --- Event Listeners ---

    processBtn.addEventListener('click', processText);
    swapBtn.addEventListener('click', swapTexts);
    clearBtn.addEventListener('click', clearAll);
    copyOutputBtn.addEventListener('click', copyOutputToClipboard);
});
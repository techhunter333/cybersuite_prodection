document.addEventListener('DOMContentLoaded', function() {
    const hashingForm = document.getElementById('hashing-form');
    const textToHashInput = document.getElementById('text-to-hash');
    const algorithmSelect = document.getElementById('algorithm-select');
    const generateHashBtn = document.getElementById('generate-hash-btn');

    const resultArea = document.getElementById('result-area');
    const resultTitle = document.getElementById('result-title');
    const hashedOutputTextarea = document.getElementById('hashed-output');
    const copyHashBtn = document.getElementById('copy-hash-btn');
    const errorMessageDiv = document.getElementById('error-message');

    // --- Core Hashing Logic (Client-Side - FIXED) ---
    /**
     * Secures hashes the input text using the Web Crypto API.
     * This function is the entire security mechanism for this tool.
     * @param {string} text 
     * @param {string} algo - Must be a string like 'SHA-256' or 'SHA-512'
     * @returns {Promise<string>} The hexadecimal hash string.
     */
    async function hashTextSecurely(text, algo) {
        // 1. Convert algorithm name to the exact, required format (e.g., 'SHA-512')
        // We trust the HTML selects send the correct standard format.
        const algorithmName = algo.toUpperCase(); 

        // 2. Encode the string to a buffer
        const encoder = new TextEncoder();
        const data = encoder.encode(text);

        // 3. Perform the secure hash operation
        const hashBuffer = await window.crypto.subtle.digest(
            algorithmName,
            data
        );

        // 4. Convert the result to a hexadecimal string
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        return hashHex;
    }
    // ----------------------------------------


    if (!hashingForm) return;

    hashingForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        errorMessageDiv.style.display = 'none';
        resultArea.style.display = 'none';

        const textToHash = textToHashInput.value;
        const selectedAlgorithm = algorithmSelect.value;
        let finalAlgorithm = selectedAlgorithm;

        if (!textToHash) {
            showError("Input text cannot be empty.");
            return;
        }

        generateHashBtn.disabled = true;
        generateHashBtn.textContent = 'Generating...';

        try {
            // 1. Perform the secure client-side hash
            const hashedValue = await hashTextSecurely(textToHash, selectedAlgorithm);

            resultTitle.textContent = `Hashed Output (${finalAlgorithm.toUpperCase()}):`;
            hashedOutputTextarea.value = hashedValue;
            resultArea.style.display = 'block';
            copyHashBtn.style.display = 'inline-block';

        } catch (error) {
            // This will catch the error if the browser's crypto API rejects the algorithm name.
            console.error('Hashing error:', error);
            
            // Note: Since we only offer SHA-256 and SHA-512 now, an error here 
            // usually means an unusual browser setup or environment issue.
            showError(`Hashing failed. Check the console for details. (Error: ${error.name || 'Unknown'})`);
            
        } finally {
            generateHashBtn.disabled = false;
            generateHashBtn.textContent = 'Generate Hash';
        }
    });

    // Copy/Legacy Copy functions remain unchanged
    copyHashBtn.addEventListener('click', function() {
        if (!hashedOutputTextarea.value) return;
        hashedOutputTextarea.select();
        hashedOutputTextarea.setSelectionRange(0, 99999);

        try {
            navigator.clipboard.writeText(hashedOutputTextarea.value).then(() => {
                copyHashBtn.textContent = 'Copied!';
                setTimeout(() => { copyHashBtn.textContent = 'Copy Hash'; }, 2000);
            }).catch(err => {
                legacyCopy();
            });
        } catch (err) {
            alert('Failed to copy hash.');
        }
    });

    function legacyCopy() {
        try {
            if (document.execCommand('copy')) {
                copyHashBtn.textContent = 'Copied!';
                setTimeout(() => { copyHashBtn.textContent = 'Copy Hash'; }, 2000);
            }
        } catch (err) {
            alert('Failed to copy hash.');
        }
    }

    function showError(message) {
        errorMessageDiv.textContent = message;
        errorMessageDiv.style.display = 'block';
        resultArea.style.display = 'none';
        copyHashBtn.style.display = 'none';
    }
});
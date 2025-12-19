document.addEventListener('DOMContentLoaded', function() {
    const cryptoForm = document.getElementById('crypto-form');
    const operationInput = document.getElementById('operation-input');
    const textDataInput = document.getElementById('text-data');
    const textDataLabel = document.getElementById('text-data-label');
    const secretKeyInput = document.getElementById('secret-key');
    const submitBtn = document.getElementById('submit-btn');

    const outputArea = document.getElementById('output-area');
    const outputText = document.getElementById('output-text');
    const outputLabel = document.getElementById('output-label');
    const copyBtn = document.getElementById('copy-btn');

    const ajaxErrorMessageDiv = document.getElementById('ajax-error-message');
    const initialServerErrorDiv = document.getElementById('initial-server-error');

    const btnEncrypt = document.getElementById('btn-encrypt');
    const btnDecrypt = document.getElementById('btn-decrypt');

    // --- UI Switcher (Same as before) ---
    function updateUIMode(mode) {
        operationInput.value = mode;
        ajaxErrorMessageDiv.style.display = 'none';
        ajaxErrorMessageDiv.textContent = '';
        if (initialServerErrorDiv) initialServerErrorDiv.style.display = 'none';

        if (mode === 'encrypt') {
            btnEncrypt.classList.add('active');
            btnDecrypt.classList.remove('active');
            textDataLabel.textContent = 'Plain Text';
            textDataInput.placeholder = 'Enter text to encrypt...';
            submitBtn.textContent = 'Encrypt Text';
            outputLabel.textContent = 'Encrypted Text (AES-GCM 256)';
        } else {
            btnDecrypt.classList.add('active');
            btnEncrypt.classList.remove('active');
            textDataLabel.textContent = 'Cipher Text (Base64)';
            textDataInput.placeholder = 'Enter Base64 text to decrypt...';
            submitBtn.textContent = 'Decrypt Text';
            outputLabel.textContent = 'Decrypted Text (Plaintext)';
        }
        outputText.value = '';
        outputArea.style.display = 'none';
        copyBtn.style.display = 'none';
        textDataInput.value = '';
    }

    btnEncrypt.addEventListener('click', () => updateUIMode('encrypt'));
    btnDecrypt.addEventListener('click', () => updateUIMode('decrypt'));

    // --- NATIVE WEB CRYPTO API FUNCTIONS (AES-GCM 256) ---

    async function getKeyMaterial(password) {
        const enc = new TextEncoder();
        return window.crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );
    }

    async function getDetails(password, salt) {
        const keyMaterial = await getKeyMaterial(password);
        return window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000, // High iteration count for security
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 }, // 256-bit Key
            true,
            ["encrypt", "decrypt"]
        );
    }

    // Buffer Helper Functions
    const buff_to_base64 = (buff) => btoa(String.fromCharCode.apply(null, new Uint8Array(buff)));
    const base64_to_buff = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

    async function encryptGCM(text, password) {
        try {
            const salt = window.crypto.getRandomValues(new Uint8Array(16)); // 16-byte salt
            const iv = window.crypto.getRandomValues(new Uint8Array(12));   // 12-byte IV (Standard for GCM)
            const key = await getDetails(password, salt);
            const enc = new TextEncoder();

            const encryptedContent = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv },
                key,
                enc.encode(text)
            );

            // Combine Salt + IV + Ciphertext
            const combined = new Uint8Array(salt.byteLength + iv.byteLength + encryptedContent.byteLength);
            combined.set(salt, 0);
            combined.set(iv, salt.byteLength);
            combined.set(new Uint8Array(encryptedContent), salt.byteLength + iv.byteLength);

            return buff_to_base64(combined);
        } catch (e) {
            console.error(e);
            throw new Error("Encryption failed.");
        }
    }

    async function decryptGCM(base64Cipher, password) {
        try {
            const combined = base64_to_buff(base64Cipher);
            
            // Extract Salt (16 bytes) and IV (12 bytes)
            if (combined.length < 28) throw new Error("Invalid ciphertext length.");
            const salt = combined.slice(0, 16);
            const iv = combined.slice(16, 28);
            const data = combined.slice(28);

            const key = await getDetails(password, salt);
            
            const decryptedContent = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                key,
                data
            );

            const dec = new TextDecoder();
            return dec.decode(decryptedContent);
        } catch (e) {
            console.error(e);
            // In GCM, a wrong key/tag throws a specific error automatically
            throw new Error("Decryption failed. Wrong key or corrupted data.");
        }
    }

    // --- FORM HANDLER ---
    cryptoForm.addEventListener('submit', async function(event) {
        event.preventDefault(); 

        ajaxErrorMessageDiv.style.display = 'none';
        outputArea.style.display = 'none';
        copyBtn.style.display = 'none';

        const currentOperation = operationInput.value;
        const textData = textDataInput.value.trim();
        const secretKey = secretKeyInput.value;

        if (!textData || !secretKey) {
            showError("Please fill in all fields.");
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = 'Processing...';

        try {
            let result = '';
            if (currentOperation === 'encrypt') {
                result = await encryptGCM(textData, secretKey);
            } else {
                result = await decryptGCM(textData, secretKey);
            }

            outputText.value = result;
            outputArea.style.display = 'block';
            copyBtn.style.display = 'block';
            // secretKeyInput.value = ''; // Optional security clear

        } catch (error) {
            showError(error.message);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = currentOperation === 'encrypt' ? 'Encrypt Text' : 'Decrypt Text';
        }
    });

    // --- UTILS ---
    function showError(message) {
        ajaxErrorMessageDiv.textContent = message;
        ajaxErrorMessageDiv.style.display = 'block';
    }

    copyBtn.addEventListener('click', () => {
        if (!outputText.value) return;
        outputText.select();
        if (navigator.clipboard) {
            navigator.clipboard.writeText(outputText.value).then(() => {
                copyBtn.textContent = 'Copied!';
                setTimeout(() => copyBtn.textContent = 'Copy to Clipboard', 2000);
            });
        } else {
            document.execCommand('copy');
        }
    });

    updateUIMode(operationInput.value || 'encrypt');
});
document.addEventListener('DOMContentLoaded', function () {
    console.log("Secure Pastebin Script Loaded.");

    // --- PART 1: LOGIC FOR THE "CREATE PASTE" PAGE (index.html) ---
    const pasteForm = document.getElementById('paste-form');

    if (pasteForm) {
        // We are on the "Create" page
        pasteForm.addEventListener('submit', handleCreatePaste);
    }

    async function handleCreatePaste(event) {
        event.preventDefault();

        const contentElem = document.getElementById('paste_content');
        const expirationElem = document.getElementById('paste_expiration');
        const statusElem = document.getElementById('form-status');
        const resultArea = document.getElementById('result-area');
        const urlInput = document.getElementById('generated-paste-url');
        const createBtn = document.getElementById('create-paste-btn');

        const plaintext = contentElem.value;
        const expiration = expirationElem.value;

        if (!plaintext.trim()) {
            statusElem.textContent = 'Content cannot be empty.';
            statusElem.className = 'error-message-pb';
            statusElem.style.display = 'block';
            return;
        }

        createBtn.disabled = true;
        statusElem.textContent = 'Generating key...';
        statusElem.className = 'info-message-pb';
        statusElem.style.display = 'block';

        try {
            // 1. Generate a secure, random encryption key
            const keyBytes = window.crypto.getRandomValues(new Uint8Array(32)); // 256-bit key
            const cryptoKey = await window.crypto.subtle.importKey(
                'raw', keyBytes, 'AES-GCM', false, ['encrypt']
            );

            // 2. Generate a random, unique IV (nonce)
            const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV

            // 3. Encrypt the plaintext
            statusElem.textContent = 'Encrypting paste...';
            const encoder = new TextEncoder();
            const encodedPlaintext = encoder.encode(plaintext);

            const encryptedBuffer = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                cryptoKey,
                encodedPlaintext
            );

            // 4. Combine [iv][ciphertext] into one buffer to store
            const encryptedBytes = new Uint8Array(encryptedBuffer);
            const combinedBuffer = new Uint8Array(iv.length + encryptedBytes.length);
            combinedBuffer.set(iv);
            combinedBuffer.set(encryptedBytes, iv.length);

            // 5. Convert the combined buffer to Base64 to send as JSON
            const encryptedContentB64 = btoa(String.fromCharCode.apply(null, combinedBuffer));

            // 6. Send the *encrypted* data to our secure API
            statusElem.textContent = 'Saving to server...';

            // --- FIX: ADDING THE application/json HEADER ---
            const response = await fetch('/pastebin/api/create', { // Uses form's action="/api/create"
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json' // CRITICAL FIX
                },
                body: JSON.stringify({
                    encrypted_content: encryptedContentB64,
                    expiration: expiration
                })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Server error.');
            }

            // 7. Create the secret URL and display it
            const keyB64 = btoa(String.fromCharCode.apply(null, keyBytes));
            const pasteId = data.paste_id;
            const shareUrl = `${window.location.origin}/pastebin/${pasteId}#${keyB64}`;

            urlInput.value = shareUrl;
            resultArea.style.display = 'block';
            statusElem.style.display = 'none';
            pasteForm.reset();

        } catch (err) {
            console.error('Failed to create paste:', err);
            statusElem.textContent = `Error: ${err.message}`;
            statusElem.className = 'error-message-pb';
        } finally {
            createBtn.disabled = false;
        }
    }

    // Copy Button for the "Create" page
    const copyUrlBtn = document.getElementById('copy-url-btn');
    if (copyUrlBtn) {
        copyUrlBtn.addEventListener('click', () => copyToClipboard(
            document.getElementById('generated-paste-url'), copyUrlBtn
        ));
    }

    // --- PART 2: LOGIC FOR THE "VIEW PASTE" PAGE (view.html) ---
    const pasteViewer = document.getElementById('paste-viewer');
    if (pasteViewer) {
        // We are on the "View" page, start decryption immediately
        handleLoadAndDecrypt();
    }

    async function handleLoadAndDecrypt() {
        const pasteId = pasteViewer.dataset.pasteId;
        const statusElem = document.getElementById('view-status');
        const contentElem = document.getElementById('paste-content-view');
        const contentArea = document.getElementById('paste-content-area');

        try {
            // 1. Get the secret key from the URL hash (#)
            const keyB64 = window.location.hash.substring(1);
            if (!keyB64) {
                throw new Error('This paste is encrypted and requires an encryption key in the URL. The link you used may be incomplete.');
            }

            // 2. Fetch the encrypted content from the API
            statusElem.textContent = 'Fetching encrypted paste...';
            statusElem.className = 'info-message-pb';
            const response = await fetch(`/pastebin/api/get/${pasteId}`);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Server error.');
            }

            // 3. Decode the Key and Content from Base64
            statusElem.textContent = 'Decrypting paste...';

            // Convert Base64 key back to bytes
            const keyBytes = new Uint8Array(atob(keyB64).split('').map(c => c.charCodeAt(0)));
            const cryptoKey = await window.crypto.subtle.importKey(
                'raw', keyBytes, 'AES-GCM', false, ['decrypt']
            );

            // Convert Base64 content back to bytes
            const combinedBuffer = new Uint8Array(atob(data.encrypted_content).split('').map(c => c.charCodeAt(0)));

            // 4. Split the buffer back into [iv] and [ciphertext]
            const iv = combinedBuffer.slice(0, 12);
            const encryptedBytes = combinedBuffer.slice(12);

            // 5. Decrypt the content
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                cryptoKey,
                encryptedBytes
            );

            // 6. Decode from bytes to a string
            const decoder = new TextDecoder();
            const plaintext = decoder.decode(decryptedBuffer);

            // 7. Display the plaintext *safely*
            contentElem.value = plaintext; // Renders as plain text in a textarea
            contentArea.style.display = 'block';
            statusElem.style.display = 'none';

            // Show copy button
            document.getElementById('copy-content-btn').style.display = 'inline-block';

        } catch (err) {
            console.error('Failed to decrypt paste:', err);
            // Check for crypto error (wrong key)
            if (err.name === 'OperationError') {
                statusElem.textContent = 'Decryption failed. The encryption key is incorrect (or the data is corrupt).';
            } else {
                statusElem.textContent = `Error: ${err.message}`;
            }
            statusElem.className = 'error-message-pb';
        }
    }

    // Copy Button for the "View" page
    const copyContentBtn = document.getElementById('copy-content-btn');
    if (copyContentBtn) {
        copyContentBtn.addEventListener('click', () => copyToClipboard(
            document.getElementById('paste-content-view'), copyContentBtn
        ));
    }

    // --- RE-USABLE HELPER FUNCTIONS ---
    function copyToClipboard(inputElement, buttonElement) {
        if (!inputElement || !inputElement.value) return;

        inputElement.select();
        inputElement.setSelectionRange(0, 99999);

        const originalText = buttonElement.textContent;

        navigator.clipboard.writeText(inputElement.value).then(() => {
            buttonElement.textContent = 'Copied!';
            setTimeout(() => { buttonElement.textContent = originalText; }, 2000);
        }).catch(err => {
            console.warn('Modern clipboard failed, falling back...');
            try {
                document.execCommand('copy');
                buttonElement.textContent = 'Copied!';
                setTimeout(() => { buttonElement.textContent = originalText; }, 2000);
            } catch (e) {
                console.error('Fallback copy failed: ', e);
                buttonElement.textContent = 'Failed!';
                setTimeout(() => { buttonElement.textContent = originalText; }, 2000);
            }
        });
    }

    // Your original countdown timer (removed for brevity but assumed functional)
});
document.addEventListener('DOMContentLoaded', function () {
    const fileForm = document.getElementById('file-form');
    const fileInput = document.getElementById('fileToProcess');
    const passwordInput = document.getElementById('password');
    const encryptBtn = document.getElementById('encrypt-btn');
    const decryptBtn = document.getElementById('decrypt-btn');
    const selectedFilenameElem = document.getElementById('selected-filename');

    const loadingSpinner = document.getElementById('loading-spinner-file');
    const statusMessageElem = document.getElementById('status-message-file');
    const errorMessageElem = document.getElementById('error-message-file');
    const progressBar = document.getElementById('progress-bar');
    const progressContainer = document.getElementById('progress-container');

    console.log("Client-Side File Encryptor (Chunked Stream) Loaded.");

    // --- 1. CRYPTOGRAPHY HELPERS (Web Crypto API) ---

    async function getKeyMaterial(password) {
        const enc = new TextEncoder();
        return window.crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );
    }

    async function deriveKey(password, salt) {
        const keyMaterial = await getKeyMaterial(password);
        return window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000, // 100k iterations for security
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    // --- 2. CHUNK PROCESSING LOGIC ---

    const CHUNK_SIZE = 10 * 1024 * 1024; // 10MB chunks (balance memory vs speed)

    async function processFile(operation) {
        const file = fileInput.files[0];
        const password = passwordInput.value;

        if (!file) return displayError('Please select a file.');
        if (!password) return displayError('Please enter a password.');

        // UI Setup
        hideMessages();
        showLoading(true);
        progressContainer.style.display = 'block';
        progressBar.style.width = '0%';
        progressBar.textContent = '0%';

        try {
            const salt = (operation === 'encrypt') 
                ? window.crypto.getRandomValues(new Uint8Array(16)) 
                : null; // Decrypt will read salt from file

            // In a real stream implementation, we would use ReadableStream.
            // For simplicity and broad compatibility, we will accumulate blobs.
            // Note: Extremely large files (>2GB) might hit browser Blob limits.
            // For >2GB support, we'd need the File System Access API (Chrome only).
            
            let resultParts = [];
            
            if (operation === 'encrypt') {
                await encryptFile(file, password, salt, resultParts);
            } else {
                await decryptFile(file, password, resultParts);
            }

            // Create Download
            const finalBlob = new Blob(resultParts, { type: 'application/octet-stream' });
            const url = window.URL.createObjectURL(finalBlob);
            const a = document.createElement('a');
            a.href = url;
            
            // Filename logic
            let dlName = file.name;
            if (operation === 'encrypt') {
                dlName += ".enc";
            } else if (dlName.endsWith(".enc")) {
                dlName = dlName.slice(0, -4);
            } else {
                dlName += ".dec";
            }
            
            a.download = dlName;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

            displayMessage(`File ${operation}ed successfully!`, 'success');
            fileForm.reset();
            selectedFilenameElem.textContent = '';

        } catch (e) {
            console.error(e);
            displayError(`Error: ${e.message}`);
        } finally {
            showLoading(false);
            setTimeout(() => { progressContainer.style.display = 'none'; }, 2000);
        }
    }

    async function encryptFile(file, password, salt, resultParts) {
        const key = await deriveKey(password, salt);
        const totalSize = file.size;
        let offset = 0;
        
        // Header: [Salt (16)]
        resultParts.push(salt);

        // We use a unique IV for each chunk to allow chunked processing securely
        // Format per chunk: [IV (12)] [Ciphertext (Size + 16 tag)]
        
        while (offset < totalSize) {
            const chunk = file.slice(offset, offset + CHUNK_SIZE);
            const arrayBuffer = await chunk.arrayBuffer();
            
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encryptedContent = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv },
                key,
                arrayBuffer
            );

            // Append IV then Encrypted Chunk
            resultParts.push(iv);
            resultParts.push(new Uint8Array(encryptedContent));

            offset += CHUNK_SIZE;
            updateProgress(offset, totalSize);
        }
    }

    async function decryptFile(file, password, resultParts) {
        // Read Salt (First 16 bytes)
        const saltBlob = file.slice(0, 16);
        const salt = new Uint8Array(await saltBlob.arrayBuffer());
        
        const key = await deriveKey(password, salt);
        const totalSize = file.size;
        let offset = 16; // Skip salt

        while (offset < totalSize) {
            // Each chunk has a 12-byte IV header
            const ivBlob = file.slice(offset, offset + 12);
            const iv = new Uint8Array(await ivBlob.arrayBuffer());
            offset += 12;

            // Calculate chunk size (Ciphertext = Plaintext + 16 byte tag)
            // Standard chunk is CHUNK_SIZE + 16 bytes tag
            // But last chunk might be smaller.
            
            // Note: To make decryption robust, we must know the exact chunk sizes.
            // In this simple implementaton, we assume standard chunking.
            // If the file was encrypted by a different tool, this loop needs logic to find boundaries.
            // For OUR tool, we know chunks are roughly CHUNK_SIZE + 16 tag.
            
            let currentEncryptedChunkSize = CHUNK_SIZE + 16; 
            if (offset + currentEncryptedChunkSize > totalSize) {
                currentEncryptedChunkSize = totalSize - offset;
            }

            const chunkBlob = file.slice(offset, offset + currentEncryptedChunkSize);
            const chunkBuffer = await chunkBlob.arrayBuffer();

            try {
                const decryptedContent = await window.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv },
                    key,
                    chunkBuffer
                );
                resultParts.push(new Uint8Array(decryptedContent));
            } catch (e) {
                throw new Error("Decryption failed. Wrong password or corrupted file.");
            }

            offset += currentEncryptedChunkSize;
            updateProgress(offset, totalSize);
        }
    }

    // --- UI Helpers ---

    function updateProgress(current, total) {
        const percent = Math.min(100, Math.round((current / total) * 100));
        progressBar.style.width = `${percent}%`;
        progressBar.textContent = `${percent}%`;
    }

    function displayMessage(msg, type) {
        statusMessageElem.textContent = msg;
        statusMessageElem.className = `status-message ${type}`;
        errorMessageElem.style.display = 'none';
    }

    function displayError(msg) {
        errorMessageElem.textContent = msg;
        errorMessageElem.style.display = 'block';
        statusMessageElem.textContent = '';
    }

    function hideMessages() {
        statusMessageElem.textContent = '';
        errorMessageElem.style.display = 'none';
    }

    function showLoading(isLoading) {
        loadingSpinner.style.display = isLoading ? 'block' : 'none';
        encryptBtn.disabled = isLoading;
        decryptBtn.disabled = isLoading;
    }

    // --- Event Listeners ---

    if (fileInput) {
        fileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                selectedFilenameElem.textContent = `Selected: ${this.files[0].name}`;
            } else {
                selectedFilenameElem.textContent = '';
            }
        });
    }

    if (encryptBtn) {
        encryptBtn.addEventListener('click', (e) => {
            e.preventDefault(); // Stop form submit
            processFile('encrypt');
        });
    }

    if (decryptBtn) {
        decryptBtn.addEventListener('click', (e) => {
            e.preventDefault(); // Stop form submit
            processFile('decrypt');
        });
    }
});
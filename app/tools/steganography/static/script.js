document.addEventListener('DOMContentLoaded', function () {
    const stegForm = document.getElementById('steganography-form');
    const imageFileInput = document.getElementById('image_file');
    const imagePreview = document.getElementById('image-preview-steg');
    const stegCanvas = document.getElementById('steg-canvas'); // The hidden canvas
    const secretMessageInput = document.getElementById('secret_message');
    const capacityCountSpan = document.getElementById('capacity-count'); // We added this ID in HTML
    const passwordInput = document.getElementById('steg-password'); 
    
    const tabEncodeBtn = document.getElementById('tab-encode-btn');
    const tabDecodeBtn = document.getElementById('tab-decode-btn');
    
    const encodeBtn = document.getElementById('encode-btn');
    const decodeBtn = document.getElementById('decode-btn');
    
    const statusMessage = document.getElementById('status-message');
    const errorMessageDiv = document.getElementById('error-message-steg');
    
    const decodedMessageArea = document.getElementById('decoded-message-area');
    const decodedMessageTextElem = document.getElementById('decoded_message_text');

    let currentMode = 'encode';

    console.log("Client-Side Steganography (AES-GCM + LSB) Loaded.");

    // --- 1. CRYPTOGRAPHY FUNCTIONS (AES-GCM 256) ---

    async function getKey(password) {
        const enc = new TextEncoder();
        return window.crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );
    }

    async function deriveSharedKey(password, salt) {
        const keyMaterial = await getKey(password);
        return window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000, // Strong iteration count
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    // --- 2. IMAGE & PIXEL LOGIC ---

    function getImageData(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const img = new Image();
                img.onload = () => {
                    // Draw to hidden canvas to get pixel data
                    stegCanvas.width = img.width;
                    stegCanvas.height = img.height;
                    const ctx = stegCanvas.getContext('2d', { willReadFrequently: true });
                    ctx.drawImage(img, 0, 0);
                    resolve(ctx.getImageData(0, 0, img.width, img.height));
                };
                img.src = e.target.result;
                
                // Update preview while we are here
                imagePreview.src = e.target.result;
                imagePreview.style.display = 'block';
            };
            reader.readAsDataURL(file);
        });
    }

    // Pseudo-Random Generator (Seeded by Password)
    // We need this to scatter pixels randomly but deterministically
    function mulberry32(a) {
        return function() {
            var t = a += 0x6D2B79F5;
            t = Math.imul(t ^ (t >>> 15), t | 1);
            t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
            return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
        }
    }

    function passwordToSeed(password) {
        let hash = 0;
        for (let i = 0; i < password.length; i++) {
            hash = ((hash << 5) - hash) + password.charCodeAt(i);
            hash |= 0; // Convert to 32bit integer
        }
        return Math.abs(hash);
    }

    function getShuffledIndices(totalPixels, password) {
        // Create an array of indices [0, 1, 2, ... totalPixels]
        // This can be heavy for 4K images, but fine for standard web images
        const indices = new Uint32Array(totalPixels);
        for (let i = 0; i < totalPixels; i++) indices[i] = i;

        // Fisher-Yates Shuffle using our seeded random
        const seed = passwordToSeed(password);
        const random = mulberry32(seed);

        for (let i = totalPixels - 1; i > 0; i--) {
            const j = Math.floor(random() * (i + 1));
            const temp = indices[i];
            indices[i] = indices[j];
            indices[j] = temp;
        }
        return indices;
    }

    // --- 3. CORE STEGANOGRAPHY FUNCTIONS ---

    async function encodeImage() {
        const file = imageFileInput.files[0];
        const password = passwordInput.value;
        const message = secretMessageInput.value;

        if (!file || !password || !message) {
            displayError("Missing File, Password, or Message.");
            return;
        }

        setStatus("Processing: Reading Image...");
        const imageData = await getImageData(file);
        const pixels = imageData.data; // RGBA array
        const totalPixels = pixels.length / 4;

        // Step A: Encrypt the Message
        setStatus("Processing: Encrypting Data...");
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveSharedKey(password, salt);
        const enc = new TextEncoder();
        
        const encryptedContent = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            enc.encode(message)
        );

        // Structure: [Salt(16)] + [IV(12)] + [Length(4)] + [Ciphertext]
        // Length is 32-bit integer (4 bytes)
        const cipherArray = new Uint8Array(encryptedContent);
        const lenBytes = new Uint8Array(new Uint32Array([cipherArray.length]).buffer); 
        // Note: Little Endian is standard in JS TypedArrays usually, but consistent across browsers

        const payload = new Uint8Array(16 + 12 + 4 + cipherArray.length);
        payload.set(salt, 0);
        payload.set(iv, 16);
        payload.set(lenBytes, 28);
        payload.set(cipherArray, 32);

        // Convert payload to bits
        const bits = [];
        for (let byte of payload) {
            for (let i = 7; i >= 0; i--) {
                bits.push((byte >> i) & 1);
            }
        }

        if (bits.length > totalPixels * 3) {
            displayError(`Message too long for this image. Needs ${bits.length} pixels, have ${totalPixels * 3} capacity.`);
            setStatus("");
            return;
        }

        // Step B: Embed Bits (Randomized LSB)
        setStatus("Processing: Embedding Data...");
        const indices = getShuffledIndices(totalPixels, password);
        let bitIdx = 0;

        for (let i = 0; i < totalPixels; i++) {
            if (bitIdx >= bits.length) break;
            
            const pIdx = indices[i] * 4; // Index in pixel array (R,G,B,A)
            
            // Embed in R, G, B channels
            for (let c = 0; c < 3; c++) {
                if (bitIdx >= bits.length) break;
                
                // Clear LSB and OR with bit
                pixels[pIdx + c] = (pixels[pIdx + c] & 0xFE) | bits[bitIdx];
                bitIdx++;
            }
        }

        // Step C: Save Image
        setStatus("Processing: Saving...");
        const ctx = stegCanvas.getContext('2d');
        ctx.putImageData(imageData, 0, 0);
        
        stegCanvas.toBlob(blob => {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = "secure_steg_image.png"; // Must be PNG to be lossless
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            setStatus("Success! Image downloaded.");
        }, 'image/png');
    }

    async function decodeImage() {
        const file = imageFileInput.files[0];
        const password = passwordInput.value;

        if (!file || !password) {
            displayError("Missing File or Password.");
            return;
        }

        setStatus("Processing: Analyzing Image...");
        const imageData = await getImageData(file);
        const pixels = imageData.data;
        const totalPixels = pixels.length / 4;

        const indices = getShuffledIndices(totalPixels, password);
        
        // We need to extract enough bits to read the Header (Salt + IV + Length)
        // Header size = 16 + 12 + 4 = 32 bytes = 256 bits
        const headerSizeBits = 32 * 8;
        let bits = [];
        
        // 1. Extract Header
        let bitIdx = 0;
        // We don't know total length yet, so iterate carefully
        for (let i = 0; i < totalPixels; i++) {
            const pIdx = indices[i] * 4;
            for (let c = 0; c < 3; c++) {
                bits.push(pixels[pIdx + c] & 1);
                bitIdx++;
                if (bits.length >= headerSizeBits) break; // Got header
            }
            if (bits.length >= headerSizeBits) break;
        }

        // Convert bits to bytes
        const headerBytes = bitsToBytes(bits);
        const salt = headerBytes.slice(0, 16);
        const iv = headerBytes.slice(16, 28);
        // Read length (4 bytes)
        const lenView = new Uint32Array(headerBytes.slice(28, 32).buffer);
        const dataLength = lenView[0];

        if (dataLength <= 0 || dataLength > 10000000) { // Sanity check (max 10MB text)
            displayError("Invalid data structure found. Wrong password or not a steganography image.");
            setStatus("");
            return;
        }

        // 2. Extract Payload
        const totalBitsNeeded = (32 + dataLength) * 8;
        bits = []; // Reset and read everything (easier logic)
        
        // Need to re-loop to get full data
        for (let i = 0; i < totalPixels; i++) {
            if (bits.length >= totalBitsNeeded) break;
            const pIdx = indices[i] * 4;
            for (let c = 0; c < 3; c++) {
                if (bits.length >= totalBitsNeeded) break;
                bits.push(pixels[pIdx + c] & 1);
            }
        }

        const fullData = bitsToBytes(bits);
        const cipherText = fullData.slice(32);

        // 3. Decrypt
        setStatus("Processing: Decrypting...");
        try {
            const key = await deriveSharedKey(password, salt);
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                key,
                cipherText
            );

            const dec = new TextDecoder();
            const plainText = dec.decode(decryptedBuffer);
            
            decodedMessageTextElem.value = plainText;
            decodedMessageArea.style.display = 'block';
            setStatus("Success! Message revealed.");

        } catch (e) {
            console.error(e);
            displayError("Decryption failed. Wrong password or corrupted data.");
            setStatus("");
        }
    }

    function bitsToBytes(bits) {
        const bytes = new Uint8Array(Math.ceil(bits.length / 8));
        for (let i = 0; i < bytes.length; i++) {
            let byteVal = 0;
            for (let b = 0; b < 8; b++) {
                if (bits[i * 8 + b]) {
                    byteVal |= (1 << (7 - b));
                }
            }
            bytes[i] = byteVal;
        }
        return bytes;
    }

    // --- UI HELPERS ---

    function displayError(msg) {
        errorMessageDiv.textContent = msg;
        errorMessageDiv.style.display = 'block';
        setTimeout(() => errorMessageDiv.style.display = 'none', 5000);
    }

    function setStatus(msg) {
        statusMessage.textContent = msg;
    }

    function updateMode(mode) {
        currentMode = mode;
        document.querySelectorAll('.tab-content-steg').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.tab-link-steg').forEach(el => el.classList.remove('active'));
        
        document.getElementById(`${mode}-tab-steg`).classList.add('active');
        document.getElementById(`tab-${mode}-btn`).classList.add('active');
        
        decodedMessageArea.style.display = 'none';
        errorMessageDiv.style.display = 'none';
        statusMessage.textContent = '';
    }

    // --- EVENT LISTENERS ---

    tabEncodeBtn.addEventListener('click', () => updateMode('encode'));
    tabDecodeBtn.addEventListener('click', () => updateMode('decode'));

    encodeBtn.addEventListener('click', (e) => {
        e.preventDefault();
        encodeImage();
    });

    decodeBtn.addEventListener('click', (e) => {
        e.preventDefault();
        decodeImage();
    });

    // Image file selection preview
    imageFileInput.addEventListener('change', async function() {
        if (this.files && this.files[0]) {
            const file = this.files[0];
            imagePreview.src = URL.createObjectURL(file);
            imagePreview.style.display = 'block';
            
            // Estimate capacity
            const img = new Image();
            img.onload = () => {
                const totalPixels = img.width * img.height;
                const bytesCapacity = Math.floor((totalPixels * 3) / 8) - 32; // Minus header
                if (capacityCountSpan) capacityCountSpan.textContent = bytesCapacity > 0 ? bytesCapacity : 0;
            };
            img.src = URL.createObjectURL(file);
        }
    });
});
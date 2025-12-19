document.addEventListener('DOMContentLoaded', function () {
    console.log("Digital Signature Script Loaded (Client-Side Mode).");

    // --- 1. DOM Elements (Matched to YOUR HTML) ---
    const signatureForm = document.getElementById('signature-form');
    
    // Input Type Radio Buttons
    const inputTypeTextRadio = document.getElementById('inputTypeText');
    const inputTypeFileRadio = document.getElementById('inputTypeFile');
    
    // Areas to toggle
    const textInputArea = document.getElementById('text-input-area');
    const fileInputArea = document.getElementById('file-input-area');
    
    // Actual Inputs
    const inputTextElem = document.getElementById('inputText');
    const inputFileElem = document.getElementById('inputFile');
    const selectedFilenameElem = document.getElementById('selected-sig-filename');
    const secretKeyElem = document.getElementById('secretKey');
    const signatureToVerifyElem = document.getElementById('signatureToVerify');
    
    // Operation (Hidden input & Tabs)
    const operationInput = document.getElementById('operation'); 
    const tabLinks = document.querySelectorAll('.tab-link');
    const signTabContent = document.getElementById('sign-options-content');
    const verifyTabContent = document.getElementById('verify-options-content');

    // Buttons & Outputs
    const processBtn = document.getElementById('process-sig-btn');
    const loadingSpinner = document.getElementById('loading-spinner-sig');
    const errorMessageDiv = document.getElementById('error-message-sig');
    const resultsArea = document.getElementById('results-area-sig');

    // Result Fields
    const resultOperationElem = document.getElementById('result-operation');
    const resultDataHashElem = document.getElementById('result-data-hash');
    const signatureResultGroup = document.getElementById('signature-result-group');
    const resultSignatureElem = document.getElementById('result-signature');
    const copySignatureBtn = document.getElementById('copy-signature-btn');
    const verificationStatusGroup = document.getElementById('verification-status-group');
    const resultVerificationStatusElem = document.getElementById('result-verification-status');
    const resultMessageTextElem = document.getElementById('result-message-text');

    // --- 2. UI TOGGLE FUNCTIONS ---

    function toggleInputType() {
        if (inputTypeTextRadio && inputTypeTextRadio.checked) {
            textInputArea.style.display = 'block';
            fileInputArea.style.display = 'none';
        } else {
            textInputArea.style.display = 'none';
            fileInputArea.style.display = 'block';
        }
    }

    function switchTab(clickedTab) {
        // Update Tabs UI
        tabLinks.forEach(l => l.classList.remove('active'));
        clickedTab.classList.add('active');

        // Show/Hide Content Areas
        const op = clickedTab.dataset.op;
        if (op === 'sign') {
            signTabContent.classList.add('active');
            verifyTabContent.classList.remove('active');
            processBtn.textContent = "Process (Sign)";
        } else {
            verifyTabContent.classList.add('active');
            signTabContent.classList.remove('active');
            processBtn.textContent = "Process (Verify)";
        }

        // Update Hidden Input
        operationInput.value = op;
        
        // Clear results when switching tabs
        hideMessages();
    }

    function displayError(message) {
        errorMessageDiv.textContent = message;
        errorMessageDiv.style.display = 'block';
        resultsArea.style.display = 'none';
    }

    function hideMessages() {
        errorMessageDiv.style.display = 'none';
        resultsArea.style.display = 'none';
    }

    function showLoading(isLoading) {
        loadingSpinner.style.display = isLoading ? 'block' : 'none';
        processBtn.disabled = isLoading;
    }

    // --- 3. CRYPTO LOGIC (Web Crypto API) ---

    async function generateHMAC(keyString, dataBuffer) {
        const enc = new TextEncoder();
        const keyData = enc.encode(keyString);
        const key = await window.crypto.subtle.importKey(
            "raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
        );
        const signature = await window.crypto.subtle.sign("HMAC", key, dataBuffer);
        return bufferToHex(signature);
    }

    async function calculateHash(dataBuffer) {
        const hashBuffer = await window.crypto.subtle.digest("SHA-256", dataBuffer);
        return bufferToHex(hashBuffer);
    }

    function bufferToHex(buffer) {
        return [...new Uint8Array(buffer)]
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    function readFileAsBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(reader.error);
            reader.readAsArrayBuffer(file);
        });
    }

    // --- 4. FORM HANDLER (FIXED) ---
    // Changed to listen for CLICK on the button, not SUBMIT on the form
    
    if (processBtn) {
        processBtn.addEventListener('click', async function(event) {
            // No preventDefault needed for type="button", but logic remains same
            hideMessages();

            const keyString = secretKeyElem.value.trim();
            if (!keyString) return displayError('Secret Key is required.');

            const operation = operationInput.value;
            let dataBuffer;

            try {
                showLoading(true);

                // Get Data based on active radio button
                if (inputTypeTextRadio.checked) {
                    const text = inputTextElem.value;
                    if (!text && operation === 'sign') throw new Error("Input text cannot be empty.");
                    dataBuffer = new TextEncoder().encode(text);
                } else {
                    if (!inputFileElem.files.length) throw new Error("Please select a file.");
                    dataBuffer = await readFileAsBuffer(inputFileElem.files[0]);
                }

                // Perform Crypto Operations
                const hashHex = await calculateHash(dataBuffer);
                const calculatedSig = await generateHMAC(keyString, dataBuffer);

                // Display Results
                resultOperationElem.textContent = operation === 'sign' ? 'Signed' : 'Verified';
                resultDataHashElem.textContent = hashHex;

                if (operation === 'sign') {
                    resultSignatureElem.textContent = calculatedSig;
                    
                    resultMessageTextElem.textContent = "Success: Signature generated locally.";
                    resultMessageTextElem.className = "info-text";
                    resultMessageTextElem.style.color = "green";

                    signatureResultGroup.style.display = 'block';
                    if(copySignatureBtn) copySignatureBtn.style.display = 'inline-block';
                    verificationStatusGroup.style.display = 'none';
                } 
                else {
                    // Verify Mode
                    const userSig = signatureToVerifyElem.value.trim().toLowerCase();
                    if (!userSig) throw new Error("Please enter the signature to verify.");

                    resultSignatureElem.textContent = userSig; 
                    const isValid = (userSig === calculatedSig);
                    
                    resultVerificationStatusElem.textContent = isValid ? "VALID" : "INVALID";
                    resultVerificationStatusElem.className = isValid ? "status-text valid" : "status-text invalid";
                    resultVerificationStatusElem.style.color = isValid ? "green" : "red";

                    if (isValid) {
                        resultMessageTextElem.textContent = "Success: The file is authentic and unmodified.";
                        resultMessageTextElem.style.color = "green";
                    } else {
                        resultMessageTextElem.textContent = "Warning: Mismatch! The file has been modified or the key is wrong.";
                        resultMessageTextElem.style.color = "red";
                    }

                    signatureResultGroup.style.display = 'block';
                    if(copySignatureBtn) copySignatureBtn.style.display = 'none';
                    verificationStatusGroup.style.display = 'block';
                }

                resultsArea.style.display = 'block';

            } catch (error) {
                console.error(error);
                displayError(error.message);
            } finally {
                showLoading(false);
            }
        });
    }

    // --- 5. EVENT LISTENERS ---

    if (inputTypeTextRadio) inputTypeTextRadio.addEventListener('change', toggleInputType);
    if (inputTypeFileRadio) inputTypeFileRadio.addEventListener('change', toggleInputType);

    tabLinks.forEach(link => {
        link.addEventListener('click', () => switchTab(link));
    });

    if(inputFileElem) {
        inputFileElem.addEventListener('change', () => {
            if (inputFileElem.files.length > 0) {
                selectedFilenameElem.textContent = `Selected: ${inputFileElem.files[0].name}`;
            } else {
                selectedFilenameElem.textContent = "";
            }
        });
    }

    if (copySignatureBtn) {
        copySignatureBtn.addEventListener('click', () => {
            const text = resultSignatureElem.textContent;
            if (text && text !== 'N/A') {
                navigator.clipboard.writeText(text);
                const original = copySignatureBtn.textContent;
                copySignatureBtn.textContent = "Copied!";
                setTimeout(() => copySignatureBtn.textContent = original, 1500);
            }
        });
    }

    // Initial UI Set
    toggleInputType();
});
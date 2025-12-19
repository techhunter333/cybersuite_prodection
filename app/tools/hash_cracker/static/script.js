document.addEventListener('DOMContentLoaded', function () {
    const crackerForm = document.getElementById('cracker-form');
    const targetHashInput = document.getElementById('targetHash');
    const hashTypeSelect = document.getElementById('hashType');
    const wordlistDefaultRadio = document.getElementById('wordlistDefault');
    const wordlistUploadRadio = document.getElementById('wordlistUpload');
    const wordlistFileInputArea = document.getElementById('wordlist-file-input-area');
    const wordlistFileInput = document.getElementById('wordlistFile');
    const crackBtn = document.getElementById('crack-btn');
    
    const loadingSpinner = document.getElementById('loading-spinner-hc');
    const statusMessageElem = document.getElementById('status-message-hc');
    const errorMessageDiv = document.getElementById('error-message-hc');
    const resultsArea = document.getElementById('results-area-hc');

    // Result display elements
    const resultStatusElem = document.getElementById('result-status-hc');
    const resultPasswordElem = document.getElementById('result-password-hc');
    const resultAttemptsElem = document.getElementById('result-attempts-hc');

    console.log("Hash Cracker Script Loaded.");

    function displayError(message) {
        errorMessageDiv.textContent = message;
        errorMessageDiv.style.display = 'block';
        statusMessageElem.textContent = '';
        resultsArea.style.display = 'none';
    }
    function displayStatus(message, type = 'info') {
        statusMessageElem.textContent = message;
        statusMessageElem.className = `status-message-hc ${type}`;
        errorMessageDiv.style.display = 'none';
    }
    function hideMessages() {
        errorMessageDiv.style.display = 'none';
        statusMessageElem.textContent = '';
    }
    function showLoading(isLoading) {
    loadingSpinner.style.display = isLoading ? 'block' : 'none';
    crackBtn.disabled = isLoading;

    // [THE FIX] Find the <span> inside the button and change its text
    const btnSpan = crackBtn.querySelector('span');
    if (btnSpan) {
        btnSpan.textContent = isLoading ? 'Cracking...' : 'Attempt to Crack Hash';
    } else {
        // Fallback for safety
        crackBtn.textContent = isLoading ? 'Cracking...' : 'Attempt to Crack Hash';
    }

    if (isLoading) resultsArea.style.display = 'none';
}
    
    function toggleWordlistInput() {
        if (wordlistUploadRadio.checked) {
            wordlistFileInputArea.style.display = 'block';
        } else {
            wordlistFileInputArea.style.display = 'none';
        }
    }
    if(wordlistDefaultRadio && wordlistUploadRadio) {
        wordlistDefaultRadio.addEventListener('change', toggleWordlistInput);
        wordlistUploadRadio.addEventListener('change', toggleWordlistInput);
    }

    if(crackerForm) {
        crackerForm.addEventListener('submit', async function(event) {
            event.preventDefault();
            hideMessages();
            
            const targetHash = targetHashInput.value.trim();
            const hashType = hashTypeSelect.value;
            const wordlistOption = document.querySelector('input[name="wordlistOption"]:checked').value;

            if (!targetHash) {
                displayError('Target hash cannot be empty.');
                return;
            }
            if (wordlistOption === 'upload' && (!wordlistFileInput.files || wordlistFileInput.files.length === 0)) {
                displayError('Please select a wordlist file when "Upload" option is chosen.');
                return;
            }

            showLoading(true);
            displayStatus('Attempting to crack hash... This may take some time depending on wordlist size.', 'info');

            const formData = new FormData(crackerForm);
            
            try {
                // *** THE FIX IS HERE ***
                const response = await fetch('/hash-cracker/crack', {
                    method: 'POST',
                    body: formData,
                });

                const responseText = await response.text();
                let data;
                try {
                    data = JSON.parse(responseText);
                } catch(e) {
                    console.error("Failed to parse JSON from cracker server:", e, "Raw Response:", responseText);
                    displayError("Received an invalid response from the server (not JSON). Check Flask console.");
                    return;
                }

                if (!response.ok || data.error) {
                    displayError(data.error || `Server error: ${response.statusText || response.status}`);
                    resultsArea.style.display = 'none';
                    return;
                }

                resultStatusElem.textContent = data.status ? data.status.replace(/_/g, ' ').toUpperCase() : 'UNKNOWN';
                resultStatusElem.className = `status-text-hc ${data.status || 'error'}`;

                if (data.status === 'found') {
                    resultPasswordElem.textContent = data.password;
                    displayStatus('Password found!', 'success');
                } else if (data.status === 'not_found') {
                    resultPasswordElem.textContent = '--- NOT FOUND ---';
                    displayStatus('Password not found in the provided wordlist.', 'info');
                } else if (data.status === 'timeout') {
                    resultPasswordElem.textContent = '--- TIMEOUT ---';
                    displayStatus('Cracking attempt timed out on the server. Try a smaller wordlist.', 'error');
                } else {
                    resultPasswordElem.textContent = '---';
                }
                resultAttemptsElem.textContent = data.attempts !== undefined ? data.attempts.toLocaleString() : 'N/A';
                resultsArea.style.display = 'block';

            } catch (error) {
                console.error("Hash cracking client-side error:", error);
                displayError("An unexpected client-side error occurred. Check console.");
            } finally {
                showLoading(false);
            }
        });
    }

    toggleWordlistInput();
});
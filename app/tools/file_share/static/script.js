document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('fileInput');
    const uploadBtn = document.getElementById('upload-btn');
    const statusText = document.getElementById('status-text');
    const progressBar = document.getElementById('progress-bar');
    const progressContainer = document.getElementById('progress-container');
    const resultArea = document.getElementById('result-area');
    const shareLinkInput = document.getElementById('share-link');
    const copyBtn = document.getElementById('copy-btn');

    // UI: Update filename on select
    if(fileInput) {
        fileInput.addEventListener('change', () => {
            if(fileInput.files.length > 0) {
                document.getElementById('file-label').textContent = fileInput.files[0].name;
            }
        });

        // FORM HANDLER
        document.getElementById('upload-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            if(!fileInput.files.length) return alert("Select a file");

            const file = fileInput.files[0];
            progressContainer.style.display = 'block';
            uploadBtn.disabled = true;

            try {
                // 1. Generate Key
                statusText.textContent = "Generating Key...";
                const key = await window.crypto.subtle.generateKey(
                    { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
                );

                // 2. Encrypt File
                statusText.textContent = "Encrypting...";
                const iv = window.crypto.getRandomValues(new Uint8Array(12));
                const fileData = await file.arrayBuffer();
                
                const encryptedData = await window.crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv }, key, fileData
                );

                // 3. Prepare Upload (Combine IV + Data)
                const blob = new Blob([iv, encryptedData], { type: 'application/octet-stream' });
                const formData = new FormData();
                formData.append('file', blob);
                formData.append('filename', file.name); // Send original name for metadata

                // 4. Upload
                statusText.textContent = "Uploading...";
                const response = await fetch('api/upload', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                if(!response.ok) throw new Error(data.error);

                // 5. Generate Link
                const exportedKey = await window.crypto.subtle.exportKey("jwk", key);
                // Convert key to Base64 string for URL hash
                const keyString = btoa(JSON.stringify(exportedKey));
                
                const link = `${window.location.origin}/file-share/download/${data.file_id}#${keyString}`;
                
                shareLinkInput.value = link;
                resultArea.style.display = 'flex';
                progressBar.style.width = '100%';
                statusText.textContent = "Encryption Complete!";

            } catch (error) {
                alert("Error: " + error.message);
                progressContainer.style.display = 'none';
            } finally {
                uploadBtn.disabled = false;
            }
        });
        
        // Copy Button Logic
        if(copyBtn) {
            copyBtn.addEventListener('click', () => {
                navigator.clipboard.writeText(shareLinkInput.value);
                const originalText = copyBtn.textContent;
                copyBtn.textContent = "Copied!";
                setTimeout(() => copyBtn.textContent = originalText, 1500);
            });
        }
    }
});
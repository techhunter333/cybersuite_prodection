document.addEventListener('DOMContentLoaded', function () {
    const urlInput = document.getElementById('url-to-trace-input');
    const traceBtn = document.getElementById('trace-redirect-btn');
    const loadingSpinner = document.getElementById('loading-spinner-redirect');
    const errorMessageDiv = document.getElementById('error-message-redirect');
    const resultsArea = document.getElementById('redirect-results-area');

    const originalUrlDisplay = document.getElementById('original-url-display');
    const finalUrlLink = document.getElementById('final-url-link');
    const finalStatusCodeElem = document.getElementById('final-status-code');
    const redirectHistoryList = document.getElementById('redirect-history-list');
    const noRedirectsMessage = document.getElementById('no-redirects-message');
    const errorWhileTracingMessage = document.getElementById('error-while-tracing-message');

    console.log("Redirect Checker Script Loaded.");

    function displayError(message) {
        console.error("Displaying Redirect Checker Error:", message);
        errorMessageDiv.textContent = message;
        errorMessageDiv.style.display = 'block';
        resultsArea.style.display = 'none';
    }
    function hideMessages() {
        errorMessageDiv.style.display = 'none';
        errorWhileTracingMessage.style.display = 'none';
        errorWhileTracingMessage.textContent = '';
    }
    
    // [FIX] Updated loading logic to preserve button icon
    function showLoading(isLoading) {
        loadingSpinner.style.display = isLoading ? 'block' : 'none';
        traceBtn.disabled = isLoading;
        
        const btnSpan = traceBtn.querySelector('span');
        if (btnSpan) {
            btnSpan.textContent = isLoading ? 'Tracing...' : 'Trace URL';
        }
        
        if (isLoading) {
            resultsArea.style.display = 'none';
        }
    }
    
    function renderRedirectHistory(history) {
        redirectHistoryList.innerHTML = '';
        if (history && history.length > 0) {
            history.forEach(hop => {
                const li = document.createElement('li');
                li.classList.add('redirect-hop'); // [FIX] Added class for CSS styling
                
                let statusClass = 'status-200';
                if (hop.status_code >= 300 && hop.status_code < 400) statusClass = 'status-3xx';
                if (hop.status_code >= 400) statusClass = 'status-4xx';
                
                let hopHtml = `<span class="hop-number">Hop ${hop.hop}:</span>`;
                hopHtml += `<span class="status-code ${statusClass}">${hop.status_code}</span> `;
                hopHtml += `<span class="hop-url">${sanitizeHTML(hop.url)}</span>`;
                
                if (hop.location_header && hop.location_header !== 'Final Destination') {
                    hopHtml += `<br><span style="color:var(--text-muted); font-size:0.85rem; margin-left:20px;">➔ Location: ${sanitizeHTML(hop.location_header)}</span>`;
                } else if (hop.location_header === 'Final Destination') {
                     hopHtml += ` <span style="color:#10b981; font-weight:bold; font-size:0.85rem;">(Final Destination)</span>`;
                }
                li.innerHTML = hopHtml;
                redirectHistoryList.appendChild(li);
            });
            noRedirectsMessage.style.display = 'none';
        } else {
            noRedirectsMessage.style.display = 'block';
        }
    }

    function sanitizeHTML(str) {
        if (str === null || typeof str === 'undefined') return '';
        const temp = document.createElement('div');
        temp.textContent = str.toString();
        return temp.innerHTML;
    }

    traceBtn.addEventListener('click', async function() {
        const urlToTrace = urlInput.value.trim();
        if (!urlToTrace) {
            displayError("Please enter a URL to trace.");
            return;
        }
        hideMessages();
        showLoading(true);
        redirectHistoryList.innerHTML = '';

        try {
            const response = await fetch('/redirect-checker/trace', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: urlToTrace })
            });
            
            const data = await response.json();

            if (!response.ok) {
                displayError(data.error || `Error: ${response.statusText}`);
                return;
            }
            
            originalUrlDisplay.textContent = data.original_url || urlToTrace;
            finalUrlLink.textContent = data.final_url || 'N/A';
            finalUrlLink.href = (data.final_url && data.final_url !== 'N/A') ? data.final_url : '#';
            finalStatusCodeElem.textContent = data.final_status_code || 'N/A';

            // Color code the final status
            const code = parseInt(data.final_status_code);
            if(code >= 400) finalStatusCodeElem.style.color = '#ef4444';
            else if(code >= 300) finalStatusCodeElem.style.color = '#f59e0b';
            else finalStatusCodeElem.style.color = '#10b981';

            renderRedirectHistory(data.redirect_history || []);

            if(data.error_while_tracing){
                errorWhileTracingMessage.textContent = "Note: " + data.error_while_tracing;
                errorWhileTracingMessage.style.display = 'block';
            }

            resultsArea.style.display = 'block';

        } catch (error) {
            console.error("URL Tracing client-side error:", error);
            displayError("An unexpected client-side error occurred. Check console.");
        } finally {
            showLoading(false);
        }
    });
});
document.addEventListener('DOMContentLoaded', function () {
    const fetchBtn = document.getElementById('fetch-feeds-btn');
    const loadingSpinner = document.getElementById('loading-spinner-ti');
    const statusMessageElem = document.getElementById('status-message-ti');
    const feedErrorsDisplay = document.getElementById('feed-errors-display');
    const feedErrorsList = document.getElementById('feed-errors-list');
    
    const feedItemsContainer = document.getElementById('feed-items-container');
    const feedListElem = document.getElementById('feed-list');
    const noFeedsMessageElem = document.getElementById('no-feeds-message');
    const totalFetchedInfoElem = document.getElementById('total-fetched-info');

    // --- HELPER FUNCTIONS ---
    function displayAppError(message) {
        statusMessageElem.textContent = message;
        statusMessageElem.className = 'alert error'; // Use global alert class
        feedItemsContainer.style.display = 'none';
    }
    
    function displayStatus(message) {
        statusMessageElem.textContent = message;
        statusMessageElem.className = ''; // Reset class
    }
    
    function hideStatusMessages() {
        statusMessageElem.textContent = '';
        statusMessageElem.className = '';
        feedErrorsDisplay.style.display = 'none';
        feedErrorsList.innerHTML = '';
    }
    
    function showLoading(isLoading) {
        loadingSpinner.style.display = isLoading ? 'block' : 'none';
        fetchBtn.disabled = isLoading;
        const btnSpan = fetchBtn.querySelector('span');
        const btnIcon = fetchBtn.querySelector('i');
        
        if (isLoading) {
            if(btnSpan) btnSpan.textContent = 'Fetching...';
            if(btnIcon) btnIcon.classList.add('fa-spin');
            displayStatus('Fetching latest intelligence...');
        } else {
            if(btnSpan) btnSpan.textContent = 'Fetch Latest Feeds';
            if(btnIcon) btnIcon.classList.remove('fa-spin');
        }
    }
    
    function sanitizeHTML(str) {
        if (!str) return '';
        const temp = document.createElement('div');
        temp.textContent = str;
        return temp.innerHTML;
    }
    
    function formatFeedDate(isoDateString) {
        if (!isoDateString) return 'Date N/A';
        try {
            const date = new Date(isoDateString);
            return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        } catch (e) {
            return isoDateString;
        }
    }

    // --- RENDER FUNCTION ---
    function renderFeedItem(item) {
        const li = document.createElement('li');
        li.classList.add('feed-item');

        const title = sanitizeHTML(item.title);
        const link = item.link && item.link !== '#' ? sanitizeHTML(item.link) : null;
        const published = formatFeedDate(item.published_iso);
        const source = sanitizeHTML(item.source);
        const summary = sanitizeHTML(item.summary);

        li.innerHTML = `
            <a href="${link}" target="_blank" rel="noopener noreferrer">
                <div class="item-header">
                    <span class="item-source">${source}</span>
                    <span class="item-date">${published}</span>
                </div>
                <h3 class="item-title">${title}</h3>
                <p class="item-summary">${summary}</p>
            </a>
        `;
        feedListElem.appendChild(li);
    }

    // --- EVENT LISTENER ---
    fetchBtn.addEventListener('click', async function() {
        hideStatusMessages();
        showLoading(true);
        feedListElem.innerHTML = ''; 
        if (noFeedsMessageElem) noFeedsMessageElem.style.display = 'none';
        if (totalFetchedInfoElem) totalFetchedInfoElem.textContent = '';

        try {
            // [FIX] Use relative path 'get-feed' so it works regardless of blueprint prefix
            const response = await fetch('get-feed'); 
            const data = await response.json();

            if (!response.ok) {
                displayAppError(data.error || `Failed to fetch feeds: ${response.statusText}`);
                return; 
            }

            // Handle Partial Errors
            if (data.errors && data.errors.length > 0) {
                feedErrorsDisplay.style.display = 'block';
                data.errors.forEach(err => {
                    const li = document.createElement('li');
                    li.innerHTML = `<strong>${sanitizeHTML(err.source)}:</strong> ${sanitizeHTML(err.error_message)}`;
                    feedErrorsList.appendChild(li);
                });
            }

            // Render Items
            if (data.feed_items && data.feed_items.length > 0) {
                data.feed_items.forEach(renderFeedItem);
                if (totalFetchedInfoElem) {
                    totalFetchedInfoElem.textContent = `Displaying ${data.feed_items.length} of ${data.total_fetched} items.`;
                }
                displayStatus(""); // Clear loading message on success
            } else {
                if (noFeedsMessageElem) {
                    noFeedsMessageElem.style.display = 'block';
                    noFeedsMessageElem.innerHTML = "No feed items found. Sources may be unavailable.";
                }
                displayStatus("");
            }

        } catch (error) {
            console.error("Client-side error:", error);
            displayAppError("An unexpected error occurred. Check console.");
        } finally {
            showLoading(false);
        }
    });
});
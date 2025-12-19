document.addEventListener('DOMContentLoaded', function () {
    const lookupForm = document.getElementById('lookup-form');
    const indicatorTypeSelect = document.getElementById('indicatorType');
    const valueInputArea = document.getElementById('value-input-area');
    const indicatorValueInput = document.getElementById('indicatorValue');
    const indicatorValueLabel = document.getElementById('indicatorValueLabel');
    const fileInputArea = document.getElementById('file-input-area-lookup');
    const indicatorFileInput = document.getElementById('indicatorFile');
    const selectedFilenameElem = document.getElementById('selected-lookup-filename');
    const lookupBtn = document.getElementById('lookup-btn');

    const loadingSpinner = document.getElementById('loading-spinner-lookup');
    const errorMessageDiv = document.getElementById('error-message-lookup');
    const resultsArea = document.getElementById('results-area-lookup');

    // Result Elements
    const analyzedIndicatorTypeElem = document.getElementById('analyzed-indicator-type');
    const analyzedIndicatorValueElem = document.getElementById('analyzed-indicator-value');
    
    // Hash Elements
    const fileUploadHashesResultElem = document.getElementById('file-upload-hashes-result');
    const fileMd5Elem = document.getElementById('file-md5-hash');
    const fileSha1Elem = document.getElementById('file-sha1-hash');
    const fileSha256Elem = document.getElementById('file-sha256-hash');
    
    // VT Elements
    const vtResultArea = document.getElementById('virustotal-result-area');
    const vtSummaryDiv = document.getElementById('vt-summary');
    const vtDetectionRatioElem = document.getElementById('vt-detection-ratio');
    const vtScanDateElem = document.getElementById('vt-scan-date');
    const vtPermalinkElem = document.getElementById('vt-permalink');
    const vtErrorElem = document.getElementById('vt-error');
    const vtDetailsToggle = document.getElementById('vt-details-toggle');
    const vtJsonOutputElem = document.getElementById('virustotal-json-output');
    
    // URLhaus Elements
    const urlhausResultArea = document.getElementById('urlhaus-result-area');
    const urlhausStatusElem = document.getElementById('urlhaus-status');
    const urlhausThreatElem = document.getElementById('urlhaus-threat');
    const urlhausTagsElem = document.getElementById('urlhaus-tags');
    const urlhausReporterElem = document.getElementById('urlhaus-reporter');
    const urlhausLinkElem = document.getElementById('urlhaus-link');
    const urlhausErrorElem = document.getElementById('urlhaus-error');
    
    // Network Intel Elements
    const networkIntelArea = document.getElementById('network-intel-area');
    const ptrRecordsResultElem = document.getElementById('ptr-records-result');
    const ptrRecordsListElem = document.getElementById('ptr-records-list');
    const dnsRecordsResultElem = document.getElementById('dns-records-result');
    const dnsRecordsListElem = document.getElementById('dns-records-list');
    const abuseipdbResultElem = document.getElementById('abuseipdb-result');
    const abuseConfidenceScoreElem = document.getElementById('abuse-confidence-score');
    const abuseIspElem = document.getElementById('abuse-isp');
    const abuseCountryCodeElem = document.getElementById('abuse-country-code');
    const abuseUsageTypeElem = document.getElementById('abuse-usage-type');
    const abuseErrorElem = document.getElementById('abuse-error');
    const whoisResultElem = document.getElementById('whois-result');
    const whoisOutputElem = document.getElementById('whois-output');

    console.log("Threat Lookup Script Loaded.");

    function displayError(message) {
        errorMessageDiv.textContent = message;
        errorMessageDiv.style.display = 'block';
        resultsArea.style.display = 'none'; 
    }

    function hideMessages() {
        errorMessageDiv.style.display = 'none';
        if(vtErrorElem) vtErrorElem.style.display = 'none';
        if(urlhausErrorElem) urlhausErrorElem.style.display = 'none';
        if(abuseErrorElem) abuseErrorElem.style.display = 'none';
    }

    function showLoading(isLoading) {
        loadingSpinner.style.display = isLoading ? 'block' : 'none';
        lookupBtn.disabled = isLoading;
        const btnSpan = lookupBtn.querySelector('span');
        if(btnSpan) btnSpan.textContent = isLoading ? 'Analyzing...' : 'Lookup Indicator';
        
        if (isLoading) {
            resultsArea.style.display = 'none'; 
            hideMessages();
        }
    }
    
    function sanitizeHTML(str) {
        if (!str) return '';
        const temp = document.createElement('div');
        temp.textContent = String(str);
        return temp.innerHTML;
    }
    
    function resetAllDisplaySections() {
        fileUploadHashesResultElem.style.display = 'none';
        vtResultArea.style.display = 'none';
        urlhausResultArea.style.display = 'none';
        networkIntelArea.style.display = 'none';
        if(ptrRecordsResultElem) ptrRecordsResultElem.style.display = 'none';
        if(dnsRecordsResultElem) dnsRecordsResultElem.style.display = 'none';
        if(abuseipdbResultElem) abuseipdbResultElem.style.display = 'none';
        if(whoisResultElem) whoisResultElem.style.display = 'none';
    }

    // --- UI Logic ---
    indicatorTypeSelect.addEventListener('change', function() {
        const selectedType = this.value;
        valueInputArea.style.display = 'none';
        fileInputArea.style.display = 'none';
        lookupBtn.disabled = true; 

        if (selectedType === 'file_upload') {
            fileInputArea.style.display = 'block';
            lookupBtn.disabled = false;
        } else if (selectedType) { 
            valueInputArea.style.display = 'block';
            lookupBtn.disabled = false;
            let placeholder = "Enter value...";
            let label = "Indicator Value";
            
            if (selectedType === 'file_hash') { placeholder = "MD5, SHA1, or SHA256 hash"; label="File Hash";}
            else if (selectedType === 'url') { placeholder = "http://example.com/path"; label="URL";}
            else if (selectedType === 'ip_address') { placeholder = "8.8.8.8"; label="IP Address";}
            else if (selectedType === 'domain') { placeholder = "example.com"; label="Domain";}
            
            indicatorValueInput.placeholder = placeholder;
            indicatorValueLabel.textContent = label;
        }
        
        indicatorValueInput.value = ''; 
        indicatorFileInput.value = ''; 
        if(selectedFilenameElem) selectedFilenameElem.textContent = '';
        hideMessages();
        resultsArea.style.display = 'none';
    });

    if(indicatorFileInput) {
        indicatorFileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                selectedFilenameElem.textContent = `Selected: ${this.files[0].name}`;
            } else {
                selectedFilenameElem.textContent = '';
            }
        });
    }

    // --- Main Logic ---
    lookupForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        hideMessages();
        resetAllDisplaySections(); 
        const indicatorType = indicatorTypeSelect.value;
        
        if (!indicatorType) {
            displayError("Please select an indicator type.");
            return;
        }
        
        const formData = new FormData();
        formData.append('indicatorType', indicatorType);
        let indicatorValueForDisplay = indicatorValueInput.value || (indicatorFileInput.files[0]?.name || '');

        if (indicatorType === 'file_upload') {
            if (!indicatorFileInput.files || indicatorFileInput.files.length === 0) {
                displayError('Please select a file to upload.');
                return;
            }
            formData.append('indicatorFile', indicatorFileInput.files[0]);
            indicatorValueForDisplay = indicatorFileInput.files[0].name;
        } else {
            const indicatorValue = indicatorValueInput.value.trim();
            if (!indicatorValue) {
                displayError('Please enter an indicator value.');
                return;
            }
            formData.append('indicatorValue', indicatorValue);
            indicatorValueForDisplay = indicatorValue;
        }
        
        showLoading(true);

        try {
            // [FIX] Use relative path 'lookup' to match routes.py
            const response = await fetch('lookup', {
                method: 'POST',
                body: formData, 
            });
            
            const responseText = await response.text();
            let data;
            try {
                data = JSON.parse(responseText);
            } catch (e) {
                console.error("JSON Parse Error:", e, responseText);
                displayError("Server returned invalid data.");
                return;
            }

            if (data.error && !data.virustotal) { 
                displayError(data.error);
                return;
            }

            // --- POPULATE RESULTS ---
            analyzedIndicatorTypeElem.textContent = data.type_analyzed;
            analyzedIndicatorValueElem.textContent = data.indicator_value;

            // 1. File Upload Hashes
            if (data.calculated_hashes) {
                fileUploadHashesResultElem.style.display = 'block';
                fileMd5Elem.textContent = data.calculated_hashes.md5;
                fileSha1Elem.textContent = data.calculated_hashes.sha1;
                fileSha256Elem.textContent = data.calculated_hashes.sha256;
            }

            // 2. VirusTotal
            if (data.virustotal) {
                vtResultArea.style.display = 'block';
                if (data.virustotal.error) {
                    vtErrorElem.textContent = data.virustotal.error;
                    vtErrorElem.style.display = 'block';
                    vtSummaryDiv.style.display = 'none';
                } else if (data.virustotal.data) {
                    vtSummaryDiv.style.display = 'grid';
                    const attrs = data.virustotal.data.attributes;
                    const stats = attrs.last_analysis_stats || {};
                    const malicious = stats.malicious || 0;
                    
                    let verdict = malicious > 0 ? "MALICIOUS" : "Clean";
                    let verdictClass = malicious > 0 ? "malicious" : "clean";
                    
                    vtDetectionRatioElem.textContent = `${verdict} (${malicious}/${stats.harmless + stats.undetected + malicious})`;
                    vtDetectionRatioElem.className = `vt-ratio ${verdictClass}`;
                    vtScanDateElem.textContent = new Date(attrs.last_analysis_date * 1000).toLocaleDateString();
                    
                    // Generate Link
                    let vtLink = `https://www.virustotal.com/gui/search/${encodeURIComponent(indicatorValueForDisplay)}`;
                    if(data.virustotal.data.id) {
                         // Attempt to construct specific link based on type
                         if(indicatorType.includes('file')) vtLink = `https://www.virustotal.com/gui/file/${data.virustotal.data.id}`;
                         else if(indicatorType === 'url') vtLink = `https://www.virustotal.com/gui/url/${data.virustotal.data.id}`;
                         else if(indicatorType === 'domain') vtLink = `https://www.virustotal.com/gui/domain/${data.virustotal.data.id}`;
                         else if(indicatorType === 'ip_address') vtLink = `https://www.virustotal.com/gui/ip-address/${data.virustotal.data.id}`;
                    }
                    vtPermalinkElem.href = vtLink;
                    
                    vtJsonOutputElem.textContent = JSON.stringify(data.virustotal.data, null, 2);
                }
            }
            
            // 3. URLhaus
            if (data.urlhaus) {
                urlhausResultArea.style.display = 'block';
                if (data.urlhaus.query_status === 'ok') {
                    urlhausStatusElem.textContent = data.urlhaus.url_status;
                    urlhausThreatElem.textContent = data.urlhaus.threat;
                    urlhausTagsElem.textContent = (data.urlhaus.tags || []).join(', ');
                    urlhausReporterElem.textContent = data.urlhaus.reporter;
                    urlhausLinkElem.href = data.urlhaus.urlhaus_link;
                } else {
                    urlhausStatusElem.textContent = "Not Found / Safe";
                    urlhausThreatElem.textContent = "-";
                    urlhausTagsElem.textContent = "-";
                    urlhausReporterElem.textContent = "-";
                }
            }

            // 4. AbuseIPDB
            if (data.abuseipdb && !data.abuseipdb.error) {
                abuseipdbResultElem.style.display = 'block';
                networkIntelArea.style.display = 'block';
                
                const score = data.abuseipdb.abuseConfidenceScore;
                abuseConfidenceScoreElem.textContent = score + '%';
                abuseConfidenceScoreElem.className = 'confidence-score ' + (score > 50 ? 'high' : 'low');
                
                abuseIspElem.textContent = data.abuseipdb.isp;
                abuseCountryCodeElem.textContent = data.abuseipdb.countryCode;
                abuseUsageTypeElem.textContent = data.abuseipdb.usageType;
            }

            // 5. WHOIS & DNS
            if (data.whois && data.whois !== 'N/A') {
                whoisResultElem.style.display = 'block';
                networkIntelArea.style.display = 'block';
                whoisOutputElem.textContent = typeof data.whois === 'object' ? JSON.stringify(data.whois, null, 2) : data.whois;
            }
            
            resultsArea.style.display = 'block';

        } catch (error) {
            console.error("Lookup error:", error);
            displayError("An unexpected client-side error occurred.");
        } finally {
            showLoading(false);
        }
    });

    // Initial state
    lookupBtn.disabled = true; 
});
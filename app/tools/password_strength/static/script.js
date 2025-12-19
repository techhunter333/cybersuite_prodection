document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('password-input');
    const progressBarFill = document.getElementById('progress-bar-fill');
    const strengthText = document.getElementById('strength-text');

    // Get references to the suggestion list items
    const checks = {
        length: document.getElementById('length-check'),
        lengthStrong: document.getElementById('length-check-strong'),
        uppercase: document.getElementById('uppercase-check'),
        lowercase: document.getElementById('lowercase-check'),
        number: document.getElementById('number-check'),
        symbol: document.getElementById('symbol-check')
    };

    passwordInput.addEventListener('input', function() {
        const password = passwordInput.value;
        let score = 0;
        let strengthLabel = 'Very Weak';
        let progressColor = '#d32f2f'; // Default: Red (Very Weak)

        // Reset suggestions styling to 'not-met' before each evaluation
        for (const key in checks) {
            if (checks[key]) { // Ensure the element exists
                 checks[key].className = 'not-met';
            }
        }

        // --- Scoring Logic ---
        const length = password.length;

        // 1. Length criteria
        if (length >= 8) {
            score += 25;
            if (checks.length) checks.length.className = 'met';
        }
        if (length >= 12) {
            score += 15; // Bonus for longer passwords
            if (checks.lengthStrong) checks.lengthStrong.className = 'met';
        } else if (length > 0 && length < 8) {
            score += 5 + (length * 2); 
        }

        // 2. Character Types (award points if present)
        if (/[A-Z]/.test(password)) {
            score += 15;
            if (checks.uppercase) checks.uppercase.className = 'met';
        }
        if (/[a-z]/.test(password)) {
            score += 15;
            if (checks.lowercase) checks.lowercase.className = 'met';
        }
        if (/[0-9]/.test(password)) {
            score += 15;
            if (checks.number) checks.number.className = 'met';
        }
        if (/[^A-Za-z0-9\s]/.test(password)) { // Non-alphanumeric
            score += 15;
            if (checks.symbol) checks.symbol.className = 'met';
        }

        // Cap the score at 100
        score = Math.min(score, 100);
        if (length === 0) { // If password field is empty, reset score
            score = 0;
        }

        // --- Determine Strength Label and Progress Bar Color ---
        if (score >= 90) {
            strengthLabel = 'Very Strong';
            progressColor = '#28a745'; // Dark Green
        } else if (score >= 75) {
            strengthLabel = 'Strong';
            progressColor = '#4CAF50'; // Green
        } else if (score >= 50) {
            strengthLabel = 'Medium';
            progressColor = '#ffc107'; // Yellow
        } else if (score >= 25) {
            strengthLabel = 'Weak';
            progressColor = '#fd7e14'; // Orange
        } else { // Score < 25
            strengthLabel = 'Very Weak';
            progressColor = '#d32f2f'; // Red
        }

        // Handle empty password field specifically for display
        if (length === 0) {
            strengthLabel = 'Enter a password';
            progressBarFill.textContent = ''; // No percentage for empty
            progressColor = '#4f545c'; // Neutral bar color for empty
        } else {
            progressBarFill.textContent = `${Math.round(score)}%`;
        }

        // --- Update UI Elements ---
        progressBarFill.style.width = score + '%';
        progressBarFill.style.backgroundColor = progressColor;
        strengthText.textContent = strengthLabel;
        strengthText.style.color = progressColor; 
    });

    // Trigger initial evaluation for an empty field to set defaults
    if (passwordInput) {
        passwordInput.dispatchEvent(new Event('input'));
    }
});
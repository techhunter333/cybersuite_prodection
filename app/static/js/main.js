document.addEventListener('DOMContentLoaded', () => {
    // [FIX] Mobile menu logic (from base.html)
    const sidebar = document.getElementById('sidebar');
    const mobileToggle = document.getElementById('mobileNavToggle');
    const sidebarClose = document.getElementById('sidebarClose');
    const overlay = document.getElementById('mobileOverlay');

    function openMenu() { 
        if (sidebar) sidebar.classList.add('open'); 
        if (overlay) overlay.classList.add('active'); 
    }
    function closeMenu() { 
        if (sidebar) sidebar.classList.remove('open'); 
        if (overlay) overlay.classList.remove('active'); 
    }

    if (mobileToggle) mobileToggle.addEventListener('click', openMenu);
    if (sidebarClose) sidebarClose.addEventListener('click', closeMenu);
    if (overlay) overlay.addEventListener('click', closeMenu);

    // [THEME LOGIC - Centralized here]
    const html = document.documentElement;
    const body = document.body;
    const themeToggleLink = document.querySelector('.theme-toggle-link');
    const themeIcon = themeToggleLink ? themeToggleLink.querySelector('i') : null;  // For icon swap

    function toggleTheme() {
        const newTheme = html.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
        html.setAttribute('data-theme', newTheme);
        body.className = `${newTheme} {% block body_class %}{% endblock %}`;  // [FIX] Sync body class (preserves Jinja block)
        localStorage.setItem('theme', newTheme);
        
        // [OPTIONAL] Swap icon: sun (fas fa-sun) for dark, moon (fas fa-moon) for light
        if (themeIcon) {
            themeIcon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }

    if (themeToggleLink) {
        themeToggleLink.addEventListener('click', (e) => {
            e.preventDefault();
            toggleTheme();
        });
    }
    
    // Set initial theme on load
    const savedTheme = localStorage.getItem('theme') || 'light';
    html.setAttribute('data-theme', savedTheme);
    body.className = `${savedTheme} {% block body_class %}{% endblock %}`;

    // [ORIGINAL] Sidebar collapse (unused - commented; re-add if you add #sidebarToggle)
    /*
    const toggleBtn = document.getElementById('sidebarToggle');
    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
        });
    }
    */
});
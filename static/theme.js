// theme.js

// Execute instantly to avoid Flash Of Unstyled Content (FOUC)
const currentTheme = localStorage.getItem('theme');
if (currentTheme === 'light') {
    document.documentElement.classList.add('light-mode');
}

document.addEventListener('DOMContentLoaded', () => {
    const themeToggleBtn = document.getElementById('theme-toggle');
    
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
            const isLight = document.documentElement.classList.toggle('light-mode');
            localStorage.setItem('theme', isLight ? 'light' : 'dark');
        });
    }
});

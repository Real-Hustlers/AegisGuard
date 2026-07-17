(function () {
    const mapping = {
        'ph-shield-check': '🛡',
        'ph-wifi-slash': '📡',
        'ph-squares-four': '▦',
        'ph-terminal-window': '⌨',
        'ph-warning': '⚠',
        'ph-hard-drives': '💾',
        'ph-gear': '⚙',
        'ph-bell': '🔔',
        'ph-activity': '⚡',
        'ph-warning-circle': '⚠',
        'ph-arrows-clockwise': '↻',
        'ph-check-circle': '✓',
        'ph-x-circle': '✕',
        'ph-eye': '👁',
        'ph-magnifying-glass': '🔍',
        'ph-chart-line-up': '📈',
        'ph-chart-line': '📈'
    };

    function applyIcons() {
        document.querySelectorAll('.ph').forEach((element) => {
            const className = Array.from(element.classList).find((name) => mapping[name]);
            if (className && !element.dataset.iconRendered) {
                element.textContent = mapping[className];
                element.dataset.iconRendered = 'true';
            }
        });
    }

    document.addEventListener('DOMContentLoaded', applyIcons);
})();

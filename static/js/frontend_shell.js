/*
 * AegisGuard Enterprise UI shell â€” Y7
 * Accessibility and responsive-shell behavior only.
 */

(function () {
    'use strict';

    const MOBILE_BREAKPOINT = 900;
    let previouslyFocused = null;

    function navItems() {
        return Array.from(document.querySelectorAll('.nav-item[data-target]'));
    }

    function views() {
        return Array.from(document.querySelectorAll('.view-section'));
    }

    function syncNavigationState(activeItem) {
        const activeTarget = activeItem ? activeItem.getAttribute('data-target') : null;

        navItems().forEach((item) => {
            const active = item === activeItem;
            if (active) {
                item.setAttribute('aria-current', 'page');
            } else {
                item.removeAttribute('aria-current');
            }
            item.setAttribute('aria-selected', active ? 'true' : 'false');
        });

        views().forEach((view) => {
            const active = view.id === activeTarget || view.classList.contains('active');
            view.setAttribute('aria-hidden', active ? 'false' : 'true');
        });
    }

    function closeSidebar() {
        document.body.classList.remove('sidebar-open');
        const toggle = document.getElementById('sidebarToggle');
        if (toggle) toggle.setAttribute('aria-expanded', 'false');
    }

    function toggleSidebar() {
        const open = document.body.classList.toggle('sidebar-open');
        const toggle = document.getElementById('sidebarToggle');
        if (toggle) toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    function buildResponsiveShell() {
        const topbar = document.querySelector('.topbar');
        const sidebar = document.getElementById('primarySidebar');
        if (!topbar || !sidebar || document.getElementById('sidebarToggle')) return;

        const button = document.createElement('button');
        button.id = 'sidebarToggle';
        button.className = 'y7-sidebar-toggle';
        button.type = 'button';
        button.setAttribute('aria-label', 'Open navigation');
        button.setAttribute('aria-controls', 'primarySidebar');
        button.setAttribute('aria-expanded', 'false');
        button.innerHTML = \'<span aria-hidden="true">&#9776;</span>\';
        button.addEventListener('click', toggleSidebar);
        topbar.insertBefore(button, topbar.firstChild);

        const scrim = document.createElement('div');
        scrim.className = 'y7-sidebar-scrim';
        scrim.setAttribute('aria-hidden', 'true');
        scrim.addEventListener('click', closeSidebar);
        document.body.appendChild(scrim);

        window.addEventListener('resize', () => {
            if (window.innerWidth > MOBILE_BREAKPOINT) closeSidebar();
        });
    }

    function enhanceNavigation() {
        const items = navItems();

        items.forEach((item, index) => {
            const targetId = item.getAttribute('data-target');
            item.setAttribute('role', 'button');
            item.setAttribute('tabindex', item.classList.contains('active') ? '0' : '-1');
            if (targetId) item.setAttribute('aria-controls', targetId);

            item.addEventListener('click', () => {
                items.forEach((candidate) => {
                    candidate.setAttribute('tabindex', candidate === item ? '0' : '-1');
                });
                syncNavigationState(item);
                if (window.innerWidth <= MOBILE_BREAKPOINT) closeSidebar();
            });

            item.addEventListener('keydown', (event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    item.click();
                    return;
                }

                if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
                event.preventDefault();

                const delta = event.key === 'ArrowDown' ? 1 : -1;
                const next = items[(index + delta + items.length) % items.length];
                next.setAttribute('tabindex', '0');
                item.setAttribute('tabindex', '-1');
                next.focus();
            });
        });

        syncNavigationState(
            items.find((item) => item.classList.contains('active')) || items[0]
        );
    }

    function enhanceTables() {
        document.querySelectorAll('table th').forEach((header) => {
            if (!header.hasAttribute('scope')) header.setAttribute('scope', 'col');
        });
    }

    function enhanceLiveRegions() {
        ['irStatusText', 'soarModeStatus', 'irIncidentCount'].forEach((id) => {
            const element = document.getElementById(id);
            if (element) {
                element.setAttribute('role', 'status');
                element.setAttribute('aria-live', 'polite');
            }
        });
    }

    function enhanceModal() {
        const modal = document.getElementById('alertModal');
        const close = document.getElementById('alertModalClose');
        if (!modal) return;

        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'alertModalTitle');

        const title = modal.querySelector('[style*="font-weight:700"]');
        if (title) title.id = 'alertModalTitle';
        if (close) close.setAttribute('aria-label', 'Close alert summary');

        const observer = new MutationObserver(() => {
            const active = modal.classList.contains('active');
            modal.setAttribute('aria-hidden', active ? 'false' : 'true');

            if (active) {
                previouslyFocused = document.activeElement;
                if (close) close.focus();
            } else if (
                previouslyFocused &&
                typeof previouslyFocused.focus === 'function'
            ) {
                previouslyFocused.focus();
                previouslyFocused = null;
            }
        });

        observer.observe(modal, {
            attributes: true,
            attributeFilter: ['class']
        });
    }

    function enhanceTopbar() {
        const bell = document.querySelector('.topbar .ph-bell');
        if (bell) {
            bell.setAttribute('role', 'img');
            bell.setAttribute('aria-label', 'Notifications');
        }
    }

    function initializeEnterpriseShell() {
        if (window.__aegisEnterpriseShellInitialized) return;
        window.__aegisEnterpriseShellInitialized = true;
        document.documentElement.dataset.aegisUi = 'enterprise-y7';

        buildResponsiveShell();
        enhanceNavigation();
        enhanceTables();
        enhanceLiveRegions();
        enhanceModal();
        enhanceTopbar();

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') closeSidebar();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener(
            'DOMContentLoaded',
            initializeEnterpriseShell,
            { once: true }
        );
    } else {
        initializeEnterpriseShell();
    }
})();
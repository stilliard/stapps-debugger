// The home page's tool search, hiding tools (and groups) that don't match.

import './shortcut.js';

const search = document.getElementById('search');
const tools = [...document.querySelectorAll('.tools li')];
const groups = [...document.querySelectorAll('.tool-group')];
const noResults = document.querySelector('.no-results');

search.placeholder = `Search ${tools.length} tools`;

if (location.hash === '#search') {
    search.focus();
}

search.addEventListener('input', () => {
    const words = search.value.toLowerCase().split(/\s+/).filter(Boolean);
    for (const tool of tools) {
        const text = `${tool.textContent} ${tool.closest('.tool-group').dataset.group}`.toLowerCase();
        tool.hidden = !words.every(word => text.includes(word));
    }
    for (const group of groups) {
        group.hidden = group.querySelectorAll('li:not([hidden])').length === 0;
    }
    noResults.hidden = groups.some(group => !group.hidden);
});

search.addEventListener('keydown', event => {
    if (event.key === 'Enter') {
        // opens the first match
        tools.find(tool => !tool.hidden)?.querySelector('a').click();
    } else if (event.key === 'Escape') {
        search.value = '';
        search.dispatchEvent(new Event('input'));
    }
});

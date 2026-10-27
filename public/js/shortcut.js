// The ⌘K / Ctrl K shortcut to search the tools, shown in each [data-shortcut] chip.
// On the home page it focuses the search, and on other pages it goes there.

const mac = /Mac|iPhone|iPad/.test(navigator.platform);

for (const chip of document.querySelectorAll('[data-shortcut]')) {
    chip.textContent = mac ? '⌘K' : 'Ctrl K';
}

document.addEventListener('keydown', event => {
    if (event.key.toLowerCase() !== 'k' || !(mac ? event.metaKey : event.ctrlKey)) {
        return;
    }
    event.preventDefault();
    const search = document.getElementById('search');
    if (search) {
        search.focus();
        search.select();
    } else {
        location.href = '/#search';
    }
});

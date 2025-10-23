document.addEventListener('DOMContentLoaded', () => {
    // --- DEKLARASI ELEMEN ---
    // 'hashInput' sekarang akan kita gunakan untuk semua tipe (hash, ip, domain)
    const iocInput = document.getElementById('hash-input'); 
    const filenameInput = document.getElementById('filename-input');
    const resultContent = document.getElementById('result-content');
    const copyButton = document.getElementById('copy-button');
    const templateControls = document.querySelector('.template-controls');
    const addTemplateOverlay = document.getElementById('add-template-overlay');
    const templateNameInput = document.getElementById('template-name-input');
    const templateContentInput = document.getElementById('template-content-input');
    const saveTemplateBtn = document.getElementById('save-template-btn');
    const cancelTemplateBtn = document.getElementById('cancel-template-btn');
    const dialogOverlay = document.getElementById('dialog-overlay');
    const dialogMessage = document.getElementById('dialog-message');
    const dialogCloseBtn = document.getElementById('dialog-close-btn');

    let currentCtiData = null;
    let baseTemplates = {};
    let userTemplates = {};
    let activeTemplateId = null;

    // --- TEMPLATE MANAGEMENT ---
    // (Tidak ada perubahan di: loadTemplates, renderTemplateButtons, createTemplateButton, deleteTemplate, saveNewTemplate)

    async function loadTemplates() {
        try {
            const response = await fetch('/api/templates');
            if (!response.ok) throw new Error('Failed to load base templates');
            baseTemplates = await response.json();
            const storedUserTemplates = localStorage.getItem('userCustomTemplates');
            userTemplates = storedUserTemplates ? JSON.parse(storedUserTemplates) : {};
            renderTemplateButtons();
        } catch (error) {
            console.error('Error loading templates:', error);
            templateControls.innerHTML = '<p style="color: red;">Could not load templates.</p>';
        }
    }

    function renderTemplateButtons() {
        templateControls.innerHTML = ''; 
        createTemplateButton('Raw CTI Result', 'raw', false); 
        for (const id in baseTemplates) {
            createTemplateButton(baseTemplates[id].name, id, false);
        }
        for (const id in userTemplates) {
            createTemplateButton(userTemplates[id].name, id, true); 
        }
        const addButtonIcon = `<svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="14" cy="14" r="14" fill="#D9D9D9"/>
            <path d="M13 15H7V13H13V7H15V13H21V15H15V21H13V15Z" fill="#757575"/>
        </svg>`;
        const container = document.createElement('div');
        container.className = 'template-btn-container';

        const addButton = document.createElement('button');
        addButton.className = 'template-btn add-template-btn';
        addButton.innerHTML = `Add Template${addButtonIcon}`;
        addButton.addEventListener('click', () => {
            templateNameInput.value = '';
            templateContentInput.value = '';
            addTemplateOverlay.style.display = 'flex';
        });

        container.appendChild(addButton);

        templateControls.appendChild(container);

        updateActiveButton();
    }
    
    function createTemplateButton(name, id, isDeletable) {
        const container = document.createElement('div');
        container.className = 'template-btn-container';
        const button = document.createElement('button');
        button.className = 'template-btn';
        button.textContent = name;
        button.dataset.templateId = id;
        button.addEventListener('click', () => applyTemplate(id));
        container.appendChild(button);
        if (isDeletable) {
            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'delete-template-btn';
            deleteBtn.innerHTML = '&times;'; 
            deleteBtn.title = 'Delete this template';
            deleteBtn.addEventListener('click', (e) => {
                e.stopPropagation(); 
                deleteTemplate(id, name);
            });
            container.appendChild(deleteBtn);
        }
        templateControls.appendChild(container);
    }
    
    function deleteTemplate(templateId, templateName) {
        if (confirm(`Are you sure you want to delete the template "${templateName}"?`)) {
            delete userTemplates[templateId];
            localStorage.setItem('userCustomTemplates', JSON.stringify(userTemplates));
            if (activeTemplateId === templateId) {
                applyTemplate('raw');
            }
            renderTemplateButtons();
            showDialog('Template has been deleted.');
        }
    }

    function saveNewTemplate() {
        const name = templateNameInput.value.trim();
        const content = templateContentInput.value.trim();
        if (!name || !content) {
            showDialog('Template name and content cannot be empty.');
            return;
        }
        const id = `user_${name.toLowerCase().replace(/\s+/g, '_')}_${Date.now()}`;
        userTemplates[id] = { name, content };
        localStorage.setItem('userCustomTemplates', JSON.stringify(userTemplates));
        addTemplateOverlay.style.display = 'none';
        renderTemplateButtons();
        showDialog('Template saved successfully!');
    }

    /**
     * =================================================================
     * FUNGSI BARU UNTUK MENDETEKSI TIPE IOC
     * =================================================================
     */
    function getIocType(value) {
        // Regex untuk IPv4
        const IPV4_REGEX = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        
        // Regex untuk hash umum (MD5, SHA1, SHA256)
        const HASH_REGEX = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/;

        if (IPV4_REGEX.test(value)) {
            return 'ip';
        }
        if (HASH_REGEX.test(value)) {
            return 'hash';
        }
        // Jika bukan keduanya, anggap domain
        return 'domain';
    }

    // --- CORE APPLICATION LOGIC ---

    /**
     * =================================================================
     * FUNGSI performSearch YANG DIPERBARUI
     * =================================================================
     */
    async function performSearch() {
        // --- PERUBAHAN DI SINI ---
        const iocValue = iocInput.value.trim(); // Menggunakan ID dari 'hash-input'
        const fileName = filenameInput.value.trim(); // Tetap ambil filename
        
        if (!iocValue) {
            showDialog('Please enter a value (Hash, IP, or Domain).');
            return;
        }
        
        // 1. Deteksi tipe IoC secara otomatis
        const iocType = getIocType(iocValue);
        // --- AKHIR PERUBAHAN ---

        resultContent.textContent = `Searching for ${iocType}: ${iocValue}... Please wait.`;
        currentCtiData = null;
        try {
            const response = await fetch('/api/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    // --- PERUBAHAN DI SINI ---
                    ioc_value: iocValue,  // Nilai input (hash/ip/domain)
                    ioc_type: iocType,    // Tipe yang terdeteksi
                    file_name: fileName,  // Tetap kirim filename
                    // --- AKHIR PERUBAHAN ---
                }),
            });
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            currentCtiData = await response.json();
            applyTemplate(activeTemplateId || 'raw');
        } catch (error) {
            console.error('Search error:', error);
            resultContent.textContent = `Error during search: ${error.message}`;
            currentCtiData = null;
        }
    }

    function applyTemplate(templateId) {
        if (templateId !== 'raw' && !currentCtiData) {
            showDialog('Please run a scan first to apply a template.');
            return;
        }
        activeTemplateId = templateId;
        const allTemplates = { ...baseTemplates, ...userTemplates };
        let finalContent = '';
        if (templateId === 'raw') {
            finalContent = currentCtiData ? currentCtiData.scan_output : '* Results will be displayed here after searching...';
        } else if (allTemplates[templateId]) {
            const templateContent = allTemplates[templateId].content;
            finalContent = replacePlaceholders(templateContent, currentCtiData);
        } else {
            finalContent = 'Template not found.';
        }
        resultContent.textContent = finalContent;
        updateActiveButton();
    }
    
    /**
     * =================================================================
     * FUNGSI replacePlaceholders YANG DIPERBARUI
     * =================================================================
     */
    function replacePlaceholders(templateString, data) {
        const now = new Date();
        const date = now.toLocaleDateString('id-ID', { year: 'numeric', month: 'long', day: 'numeric' });
        const time = now.toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

        return templateString
            // --- PERUBAHAN PENTING ---
            // Ganti {{hash}} menjadi {{ioc_value}} agar lebih generik
            .replace(/{{ioc_value}}/g, data.ioc_value || 'N/A')
            // --- AKHIR PERUBAHAN ---
            .replace(/{{filename}}/g, data.file_name || 'N/A')
            .replace(/{{hasil_cti}}/g, data.scan_output || 'No CTI results available.')
            .replace(/{{date}}/g, date)
            .replace(/{{time}}/g, time);
    }
    
    function updateActiveButton() {
        document.querySelectorAll('.template-btn-container').forEach(container => {
            const button = container.querySelector('.template-btn');
            if(button){
                 button.classList.toggle('active', button.dataset.templateId === activeTemplateId);
            }
        });
    }

    // --- EVENT LISTENERS ---
    // (Ganti hashInput ke iocInput untuk keypress)
    iocInput.addEventListener('keypress', (e) => e.key === 'Enter' && performSearch());
    filenameInput.addEventListener('keypress', (e) => e.key === 'Enter' && performSearch());
    
    copyButton.addEventListener('click', () => {
        navigator.clipboard.writeText(resultContent.textContent)
            .then(() => showDialog('Result copied to clipboard!'))
            .catch(err => {
                console.error('Copy failed:', err);
                showDialog('Failed to copy text.');
            });
    });
    saveTemplateBtn.addEventListener('click', saveNewTemplate);
    cancelTemplateBtn.addEventListener('click', () => addTemplateOverlay.style.display = 'none');
    dialogCloseBtn.addEventListener('click', () => dialogOverlay.style.display = 'none');
    
    function showDialog(message) {
        dialogMessage.textContent = message;
        dialogOverlay.style.display = 'flex';
    }

    // --- INISIALISASI ---
    loadTemplates();
});
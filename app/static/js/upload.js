const MAX_MB = 500;
const ALLOWED = ['.pcap', '.pcapng', '.cap'];

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const fileInfo = document.getElementById('fileInfo');
const submitBtn = document.getElementById('submitBtn');
const form = document.getElementById('uploadForm');

let selectedFile = null;

dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', () => { if (fileInput.files.length) handleFile(fileInput.files[0]); });

function handleFile(file) {
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!ALLOWED.includes(ext)) {
        alert('Invalid file type. Use .pcap, .pcapng, or .cap');
        return;
    }
    if (file.size > MAX_MB * 1024 * 1024) {
        alert(`File exceeds ${MAX_MB}MB limit`);
        return;
    }
    selectedFile = file;
    fileInfo.textContent = `${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`;
    fileInfo.classList.remove('d-none');
    submitBtn.disabled = false;
}

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!selectedFile) return;

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Uploading...';

    const fd = new FormData();
    fd.append('file', selectedFile);
    fd.append('analysis_name', document.getElementById('analysisName').value);
    fd.append('analyst_notes', document.getElementById('analystNotes').value);

    try {
        const resp = await fetch('/api/upload', { method: 'POST', body: fd });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Upload failed');
        window.location.href = `/analysis/${data.analysis_id}`;
    } catch (err) {
        alert(err.message);
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="bi bi-play-fill"></i> Start Analysis';
    }
});

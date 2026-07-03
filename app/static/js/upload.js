const MAX_MB = 500;
const ALLOWED = ['.pcap', '.pcapng', '.cap'];

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const fileInfo = document.getElementById('fileInfo');
const submitBtn = document.getElementById('submitBtn');
const form = document.getElementById('uploadForm');
const uploadProgress = document.getElementById('uploadProgress');
const uploadPhase = document.getElementById('uploadPhase');
const uploadPct = document.getElementById('uploadPct');
const uploadBar = document.getElementById('uploadBar');

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

function setUploadProgress(pct, phaseText) {
    if (uploadProgress) uploadProgress.classList.remove('d-none');
    if (uploadPhase) uploadPhase.textContent = phaseText;
    if (uploadPct) uploadPct.textContent = `${pct}%`;
    if (uploadBar) uploadBar.style.width = `${pct}%`;
}

form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!selectedFile) return;

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Uploading...';
    setUploadProgress(0, 'Uploading PCAP file...');

    const fd = new FormData();
    fd.append('file', selectedFile);
    fd.append('analysis_name', document.getElementById('analysisName').value);
    fd.append('analyst_notes', document.getElementById('analystNotes').value);

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload');

    xhr.upload.addEventListener('progress', (event) => {
        if (!event.lengthComputable) return;
        const pct = Math.min(99, Math.round((event.loaded / event.total) * 100));
        const mbDone = (event.loaded / 1024 / 1024).toFixed(1);
        const mbTotal = (event.total / 1024 / 1024).toFixed(1);
        setUploadProgress(pct, `Uploading PCAP (${mbDone} / ${mbTotal} MB)...`);
    });

    xhr.addEventListener('load', () => {
        let data = {};
        try {
            data = JSON.parse(xhr.responseText || '{}');
        } catch {
            data = {};
        }

        if (xhr.status >= 200 && xhr.status < 300 && data.analysis_id) {
            setUploadProgress(100, 'Upload complete — redirecting to analysis progress...');
            uploadBar?.classList.remove('progress-bar-animated');
            window.location.href = `/analysis/${data.analysis_id}`;
            return;
        }

        alert(data.error || 'Upload failed');
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="bi bi-play-fill"></i> Start Analysis';
        uploadProgress?.classList.add('d-none');
    });

    xhr.addEventListener('error', () => {
        alert('Upload failed — network error');
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="bi bi-play-fill"></i> Start Analysis';
        uploadProgress?.classList.add('d-none');
    });

    xhr.send(fd);
});

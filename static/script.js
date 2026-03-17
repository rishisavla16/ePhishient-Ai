let currentUrl = "";

// Allow pressing Enter to analyze without reloading
document.getElementById('urlInput').addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        checkUrl();
    }
});

// Clear Button Logic
document.getElementById('clearBtn').addEventListener('click', function() {
    document.getElementById('urlInput').value = '';
    document.getElementById('result').style.display = 'none';
    document.getElementById('urlInput').focus();

    // Reset buttons
    document.getElementById('analyzeBtn').style.display = 'block';
    document.getElementById('clearBtn').style.display = 'none';
    document.getElementById('reanalyzeBtn').style.display = 'none';
});

async function checkUrl() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) {
        showModal("Please enter a URL before analyzing.");
        return;
    }

    currentUrl = url;
    document.getElementById('urlInput').blur(); // Dismiss keyboard on mobile
    const formData = new FormData();
    formData.append('url', url);

    // Loading State
    const analyzeBtn = document.getElementById('analyzeBtn');
    const reanalyzeBtn = document.getElementById('reanalyzeBtn');
    
    // Determine active button to show loading on
    const activeBtn = analyzeBtn.style.display !== 'none' ? analyzeBtn : reanalyzeBtn;
    const originalText = activeBtn.innerText;
    
    activeBtn.innerText = "Analyzing... ⏳";
    activeBtn.disabled = true;

    try {
        const response = await fetch('/predict', { method: 'POST', body: formData });
        const data = await response.json();

    if (data.error) {
        alert(data.error);
        return;
    }

    const resultDiv = document.getElementById('result');
    const statusText = document.getElementById('statusText');
    
    // Toggle buttons (Show Clear/Reanalyze)
    analyzeBtn.style.display = 'none';
    document.getElementById('clearBtn').style.display = 'block';
    reanalyzeBtn.style.display = 'block';
    
    resultDiv.style.display = 'block';
    resultDiv.scrollIntoView({ behavior: 'smooth' });
    
    // Dynamic styling based on risk score (Green -> Red)
    const hue = 120 - (data.confidence * 120);
    resultDiv.style.backgroundColor = `hsl(${hue}, 80%, 96%)`;
    resultDiv.style.color = `hsl(${hue}, 80%, 20%)`;
    
    statusText.innerText = data.is_malicious ? "⚠️ WARNING: PHISHING DETECTED" : "✅ URL APPEARS SAFE";
    document.getElementById('confidenceScore').innerText = (data.confidence * 100).toFixed(2) + "%";
    
    // Update Gradient Marker Position
    const percentage = (data.risk_score ?? data.confidence) * 100;
    const marker = document.getElementById('riskMarker');
    
    // Update tooltip text
    document.getElementById('riskTooltip').innerText = percentage.toFixed(1) + "%";
    
    // Reset animation
    marker.style.transition = 'none';
    marker.style.left = '0%';
    void marker.offsetWidth; // Force reflow
    marker.style.transition = 'left 1s cubic-bezier(0.2, 0, 0.2, 1)';
    marker.style.left = percentage + "%";
    
    const reasonList = document.getElementById('reasonList');
    reasonList.innerHTML = '';
    data.explanation.forEach(reason => {
        const li = document.createElement('li');
        li.innerText = reason;
        reasonList.appendChild(li);
    });

    } catch (error) {
        console.error(error);
        alert("An error occurred while analyzing the URL.");
    } finally {
        activeBtn.innerText = originalText;
        activeBtn.disabled = false;
    }
}

document.getElementById('themeToggle').addEventListener('click', function() {
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    this.innerText = isDark ? '☀️' : '🌙';
});

// Share Button Logic
const shareBtn = document.getElementById('shareBtn');
const shareModal = document.getElementById('shareModal');
const customModal = document.getElementById('customModal');
const confirmModal = document.getElementById('confirmModal');

if (shareBtn) {
    shareBtn.addEventListener('click', () => {
        shareModal.style.display = "block";
    });
}

function closeShareModal() {
    if (shareModal) shareModal.style.display = "none";
}

function showModal(message) {
    if (customModal) {
        document.getElementById('modalMessage').innerText = message;
        customModal.style.display = "block";
    }
}

function closeModal() {
    if (customModal) customModal.style.display = "none";
}

let confirmCallback = null;

function showConfirmModal(message, callback) {
    if (confirmModal) {
        document.getElementById('confirmMessage').innerText = message;
        confirmModal.style.display = "block";
        confirmCallback = callback;
    }
}

function closeConfirmModal() {
    if (confirmModal) confirmModal.style.display = "none";
    confirmCallback = null;
}

if (document.getElementById('confirmYesBtn')) {
    document.getElementById('confirmYesBtn').addEventListener('click', function() {
        if (confirmCallback) confirmCallback();
        closeConfirmModal();
    });
}

// Close modal when clicking outside
window.onclick = function(event) {
    if (event.target == shareModal) {
        closeShareModal();
    }
    if (event.target == customModal) {
        closeModal();
    }
    if (event.target == confirmModal) {
        closeConfirmModal();
    }
}

function getReportText() {
    const status = document.getElementById('statusText').innerText;
    const confidence = document.getElementById('confidenceScore').innerText;
    const reasons = Array.from(document.querySelectorAll('#reasonList li')).map(li => '- ' + li.innerText).join('\n');
    return `Phishing Analysis Report\nURL: ${currentUrl}\nResult: ${status}\nConfidence: ${confidence}\n\nReasons:\n${reasons}`;
}

async function copyToClipboard() {
    const text = getReportText();
    
    // Try Clipboard API first (requires HTTPS)
    if (navigator.clipboard && navigator.clipboard.writeText) {
        try {
            await navigator.clipboard.writeText(text);
            closeShareModal();
            alert("Copied to clipboard!");
            return;
        } catch (err) {
            console.warn('Clipboard API failed, trying fallback...');
        }
    }

    // Fallback for non-secure contexts (Mobile HTTP)
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-9999px";
    textArea.setAttribute("readonly", "");
    document.body.appendChild(textArea);
    textArea.select();
    textArea.setSelectionRange(0, 99999);
    
    try {
        document.execCommand('copy');
        alert("Copied to clipboard!");
    } catch (err) {
        console.error('Fallback copy failed:', err);
    }
    document.body.removeChild(textArea);
    closeShareModal();
}

function downloadPDF() {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const text = getReportText();
    
    doc.setFontSize(16);
    doc.text("Phishing Analysis Report", 20, 20);
    
    doc.setFontSize(12);
    const splitText = doc.splitTextToSize(text.replace("🔍 Phishing Analysis Report\n", ""), 170);
    doc.text(splitText, 20, 40);
    
    doc.save("phishing-report.pdf");
    closeShareModal();
}

function retrainModel() {
    showConfirmModal("Are you sure you want to retrain the AI model? This process may take a few seconds.", async () => {
        const btn = document.querySelector('.btn-retrain'); // Select by class
        const originalText = btn.innerText;
        btn.innerText = "Training... ⏳";
        btn.disabled = true;
        
        try {
            const response = await fetch('/retrain', { method: 'POST' });
            const data = await response.json();
            showModal(data.message);
        } catch (error) {
            showModal("Error: Failed to retrain model.");
        } finally {
            btn.innerText = originalText;
            btn.disabled = false;
        }
    });
}
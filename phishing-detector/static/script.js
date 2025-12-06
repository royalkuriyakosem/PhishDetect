document.getElementById('urlForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('url').value;
    const brand = document.getElementById('brand').value;
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.textContent = 'Analyzing...';  // Loading state
    submitBtn.disabled = true;

    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, brand })
        });

        if (response.ok) {
            const data = await response.json();
            displayResults(data);
        } else {
            alert('Error: ' + await response.text());
        }
    } catch (error) {
        alert('Network error: ' + error.message);
    } finally {
        submitBtn.textContent = 'Analyze';
        submitBtn.disabled = false;
    }
});

function displayResults(data) {
    document.getElementById('results').style.display = 'block';

    // URL Score (Phase 1)
    const urlBar = document.getElementById('urlScore').querySelector('.progress-bar');
    urlBar.style.width = `${data.url_score * 100}%`;
    document.getElementById('urlValue').textContent = `Score: ${data.url_score.toFixed(3)} (Higher = Legit)`;

    // DOM Score (Phase 2)
    const domBar = document.getElementById('domScore').querySelector('.progress-bar');
    domBar.style.width = `${data.dom_score * 100}%`;
    document.getElementById('domValue').textContent = `Score: ${data.dom_score.toFixed(3)} (Higher = Matches Brand)`;

    // Fusion Score (Phase 3)
    const hybridBar = document.getElementById('hybridScore').querySelector('.progress-bar');
    hybridBar.style.width = `${data.hybrid_score * 100}%`;
    document.getElementById('hybridValue').textContent = `Score: ${data.hybrid_score.toFixed(3)} (Weighted Avg)`;

    // Final Label
    const labelEl = document.getElementById('finalLabel');
    labelEl.textContent = `${data.final_label.toUpperCase()}!`;
    labelEl.className = data.final_label.toLowerCase();
    document.getElementById('threshold').textContent = `Threshold: ${data.threshold.toFixed(2)}`;
}
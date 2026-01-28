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
    // Invert Score: 1.0 - Phishing Prob = Legitimacy Score
    const urlLegitScore = 1.0 - data.url_score;
    urlBar.style.width = `${urlLegitScore * 100}%`;
    document.getElementById('urlValue').textContent = `Score: ${urlLegitScore.toFixed(3)} (Higher = Legit)`;

    // DOM Score (Phase 2)
    const domBar = document.getElementById('domScore').querySelector('.progress-bar');
    domBar.style.width = `${data.dom_score * 100}%`;
    document.getElementById('domValue').textContent = `Score: ${data.dom_score.toFixed(3)} (Higher = Matches Brand)`;

    // Visual Score (Phase 2.5)
    const visualBar = document.getElementById('visualScore').querySelector('.progress-bar');
    visualBar.style.width = `${data.visual_score * 100}%`;
    document.getElementById('visualValue').textContent = `Score: ${data.visual_score.toFixed(3)} (Higher = Visually Similar)`;

    // Fusion Score (Phase 3)
    // User Request: Low = Phishing, High = Legit
    // Backend returns Phishing Probability (High = Phishing)
    // So we invert it: Legit Score = 1.0 - Phishing Probability
    const legitScore = 1.0 - data.hybrid_score;
    const hybridBar = document.getElementById('hybridScore').querySelector('.progress-bar');
    hybridBar.style.width = `${legitScore * 100}%`;
    document.getElementById('hybridValue').textContent = `Score: ${legitScore.toFixed(3)} (Higher = Legit)`;

    // Final Label
    const labelEl = document.getElementById('finalLabel');
    labelEl.textContent = `${data.final_label.toUpperCase()}!`;
    labelEl.className = data.final_label.toLowerCase();
    document.getElementById('threshold').textContent = `Threshold: ${data.threshold.toFixed(2)}`;
}
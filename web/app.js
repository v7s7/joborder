document.addEventListener('DOMContentLoaded', () => {
    // Set default dates
    const today = new Date().toISOString().split('T')[0];
    document.getElementById('main_date').value = today;
    document.getElementById('start_date').value = today;
    document.getElementById('end_date').value = today;
    
    // Set current date in header
    const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute:'2-digit' };
    document.getElementById('current-date').textContent = new Date().toLocaleDateString('en-US', options);

    // Fetch next job number
    fetchJobNumber();

    // Handle form submission
    document.getElementById('jobForm').addEventListener('submit', handleGenerate);
});

async function fetchJobNumber() {
    try {
        const response = await fetch('/api/get-job-no');
        const data = await response.json();
        document.getElementById('job-number-display').textContent = data.job_no;
    } catch (error) {
        console.error('Error fetching job number:', error);
    }
}

async function handleGenerate(e) {
    e.preventDefault();
    
    const btn = document.getElementById('submitBtn');
    const statusText = document.getElementById('status-text');
    const statusIndicator = document.getElementById('status-indicator');
    
    // Set busy state
    btn.disabled = true;
    btn.textContent = "Processing...";
    statusText.textContent = "GENERATING PDF...";
    statusIndicator.className = "status-indicator processing";

    // Gather data
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());

    try {
        const response = await fetch('/api/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });

        const result = await response.json();

        if (result.success) {
            alert('Success! PDF Generated.\n' + result.file);
            // Refresh job number for next one
            fetchJobNumber();
        } else {
            alert('Error: ' + result.error);
        }

    } catch (error) {
        alert('System Error: ' + error);
    } finally {
        // Reset state
        btn.disabled = false;
        btn.textContent = "Generate PDF Report";
        statusText.textContent = "READY";
        statusIndicator.className = "status-indicator ready";
    }
}

function resetForm() {
    document.getElementById('jobForm').reset();
    const today = new Date().toISOString().split('T')[0];
    document.getElementById('main_date').value = today;
    document.getElementById('start_date').value = today;
    document.getElementById('end_date').value = today;
}
function clearDuration() {
    const radios = document.querySelectorAll('.duration-section input[type="radio"]');
    radios.forEach(radio => radio.checked = false);
}
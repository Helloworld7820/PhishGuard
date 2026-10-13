/**
 * PhishGuard Main Frontend Interaction Script
 * Manages URL form submission, client validation, button loading states, and sample autofill.
 */
document.addEventListener("DOMContentLoaded", () => {
    const scannerForm = document.getElementById("scannerForm");
    const urlInput = document.getElementById("urlInput");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const btnSpinner = document.getElementById("btnSpinner");
    const btnText = document.querySelector("#analyzeBtn .btn-text");
    const btnIcon = document.querySelector("#analyzeBtn .btn-icon");
    const validationMsg = document.getElementById("clientValidationMsg");

    // Sample URL autofill handlers
    const sampleButtons = document.querySelectorAll(".btn-sample");
    sampleButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const sampleUrl = btn.getAttribute("data-url");
            if (sampleUrl && urlInput) {
                urlInput.value = sampleUrl;
                urlInput.focus();
                // Clear any lingering error message
                hideValidation();
            }
        });
    });

    function showValidation(msg) {
        if (validationMsg) {
            validationMsg.textContent = msg || "Please enter a valid URL.";
            validationMsg.classList.remove("d-none");
        }
        if (urlInput) {
            urlInput.classList.add("is-invalid");
        }
    }

    function hideValidation() {
        if (validationMsg) {
            validationMsg.classList.add("d-none");
        }
        if (urlInput) {
            urlInput.classList.remove("is-invalid");
        }
    }

    if (urlInput) {
        urlInput.addEventListener("input", () => {
            if (urlInput.value.trim().length > 0) {
                hideValidation();
            }
        });
    }

    if (scannerForm) {
        scannerForm.addEventListener("submit", (e) => {
            const rawValue = (urlInput.value || "").trim();

            if (!rawValue) {
                e.preventDefault();
                showValidation("Please enter a URL to inspect.");
                return;
            }

            if (rawValue.length > 2048) {
                e.preventDefault();
                showValidation("URL exceeds the maximum permissible limit of 2048 characters.");
                return;
            }

            // Activate loading state
            if (analyzeBtn && btnSpinner && btnText) {
                analyzeBtn.disabled = true;
                btnSpinner.classList.remove("d-none");
                if (btnIcon) btnIcon.classList.add("d-none");
                btnText.textContent = "Analyzing Features...";
            }
            
            // Allow form submission to proceed
        });
    }
});

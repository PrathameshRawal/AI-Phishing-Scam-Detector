/* ============================================================
   AI Phishing & Scam Detector - Frontend JavaScript
   Handles mode switching, input validation, API requests,
   loading states, and result display.
   ============================================================ */

(function () {
    "use strict";

    // ---- DOM references ------------------------------------------
    const btnUrl = document.getElementById("btn-url");
    const btnMessage = document.getElementById("btn-message");
    const inputText = document.getElementById("input-text");
    const inputLabel = document.getElementById("input-label");
    const inputValidation = document.getElementById("input-validation");
    const analyzeBtn = document.getElementById("analyze-btn");
    const clearBtn = document.getElementById("clear-btn");
    const samplesGrid = document.getElementById("samples-grid");
    const resultsPanel = document.getElementById("results-panel");
    const riskLevelValue = document.getElementById("risk-level-value");
    const riskScoreValue = document.getElementById("risk-score-value");
    const scoreBar = document.getElementById("score-bar");
    const warningList = document.getElementById("warning-list");
    const adviceText = document.getElementById("advice-text");
    const modelPrediction = document.getElementById("model-prediction");
    const modelConfidence = document.getElementById("model-confidence");
    const sourcesList = document.getElementById("sources-list");
    const resultDisclaimer = document.getElementById("result-disclaimer");
    const detailsToggle = document.getElementById("details-toggle");
    const detailsContent = document.getElementById("details-content");

    // ---- State ---------------------------------------------------
    let currentMode = "url";

    // ---- Sample data ---------------------------------------------
    const samples = [
        {
            type: "url",
            category: "phishing",
            text: "http://bit.ly/claim-free-iphone-now",
            label: "Suspicious shortened URL",
        },
        {
            type: "url",
            category: "phishing",
            text: "http://suspicious-bank-login.com/verify-account?id=999",
            label: "Fake bank login page",
        },
        {
            type: "url",
            category: "phishing",
            text: "http://192.168.1.50/paypal/secure-login/update-password",
            label: "IP-address based fake URL",
        },
        {
            type: "url",
            category: "legitimate",
            text: "https://en.wikipedia.org/wiki/Phishing",
            label: "Legitimate Wikipedia link",
        },
        {
            type: "message",
            category: "phishing",
            text: "Congratulations! You have won a $1000 gift card. Click here to claim your prize now.",
            label: "Fake prize scam message",
        },
        {
            type: "message",
            category: "phishing",
            text: "Urgent! Your account has been suspended. Verify your identity immediately to avoid permanent closure.",
            label: "Urgency-based phishing",
        },
        {
            type: "message",
            category: "phishing",
            text: "Dear customer, your package could not be delivered. Pay $2 processing fee to reschedule delivery.",
            label: "Fake delivery fee scam",
        },
        {
            type: "message",
            category: "legitimate",
            text: "Hi Mom, it's me. I lost my phone. Can you pick up some milk on your way home?",
            label: "Normal personal message",
        },
        {
            type: "message",
            category: "legitimate",
            text: "Your order from Amazon has been shipped and will arrive on Friday.",
            label: "Normal order update",
        },
    ];

    // ---- Mode switching ------------------------------------------
    function setMode(mode) {
        currentMode = mode;

        btnUrl.classList.toggle("active", mode === "url");
        btnMessage.classList.toggle("active", mode === "message");

        if (mode === "url") {
            inputLabel.textContent = "Enter a URL to analyze";
            inputText.placeholder = "https://example.com";
        } else {
            inputLabel.textContent = "Enter a message to analyze";
            inputText.placeholder = "Type or paste the suspicious message here...";
        }

        inputText.value = "";
        validateInput();
        renderSamples();
    }

    btnUrl.addEventListener("click", () => setMode("url"));
    btnMessage.addEventListener("click", () => setMode("message"));

    // ---- Input validation ----------------------------------------
    function validateInput() {
        const text = inputText.value.trim();

        if (text.length === 0) {
            inputValidation.textContent = "";
            inputValidation.className = "input-validation";
            analyzeBtn.disabled = true;
            return false;
        }

        if (currentMode === "url") {
            // Basic URL check -- must contain a dot or start with http
            if (!text.match(/^https?:\/\//i) && !text.includes(".")) {
                inputValidation.textContent = "Please enter a valid URL (e.g. https://example.com)";
                inputValidation.className = "input-validation error";
                analyzeBtn.disabled = true;
                return false;
            }
        }

        if (text.length < 5) {
            inputValidation.textContent = "Input is too short. Please enter more text.";
            inputValidation.className = "input-validation error";
            analyzeBtn.disabled = true;
            return false;
        }

        inputValidation.textContent = "Ready to analyze";
        inputValidation.className = "input-validation valid";
        analyzeBtn.disabled = false;
        return true;
    }

    inputText.addEventListener("input", validateInput);

    // ---- Render sample buttons -----------------------------------
    function renderSamples() {
        samplesGrid.innerHTML = "";
        const filtered = samples.filter((s) => s.type === currentMode);

        filtered.forEach((sample) => {
            const btn = document.createElement("button");
            btn.className = "sample-btn";
            btn.innerHTML =
                '<span class="sample-type ' + sample.category + '">' +
                sample.category +
                "</span>" +
                sample.label;
            btn.title = sample.text;
            btn.addEventListener("click", () => {
                inputText.value = sample.text;
                validateInput();
                inputText.focus();
            });
            samplesGrid.appendChild(btn);
        });
    }

    // ---- Analyze -------------------------------------------------
    async function runAnalysis() {
        const text = inputText.value.trim();
        if (!text) return;

        // Show loading state
        analyzeBtn.querySelector(".btn-text").hidden = true;
        analyzeBtn.querySelector(".btn-loader").hidden = false;
        analyzeBtn.disabled = true;
        resultsPanel.hidden = true;

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    text: text,
                    check_type: currentMode,
                }),
            });

            const data = await response.json();

            if (!response.ok) {
                showError(data.error || "An error occurred during analysis.");
                return;
            }

            displayResults(data);
        } catch (err) {
            showError(
                "Could not connect to the server. Make sure the Flask app is running. " +
                "This does NOT mean the input is safe."
            );
        } finally {
            analyzeBtn.querySelector(".btn-text").hidden = false;
            analyzeBtn.querySelector(".btn-loader").hidden = true;
            analyzeBtn.disabled = false;
        }
    }

    analyzeBtn.addEventListener("click", runAnalysis);

    // Allow pressing Ctrl+Enter to analyze
    inputText.addEventListener("keydown", function (e) {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            runAnalysis();
        }
    });

    // ---- Display results -----------------------------------------
    function displayResults(data) {
        resultsPanel.hidden = false;

        // Set risk class on the panel for color styling
        const riskClass = data.risk_level.toLowerCase().includes("high")
            ? "risk-high"
            : data.risk_level.toLowerCase().includes("medium")
            ? "risk-medium"
            : "risk-low";
        resultsPanel.className = "results-panel " + riskClass;

        // Risk level
        riskLevelValue.textContent = data.risk_level;

        // Risk score with animated bar
        riskScoreValue.textContent = data.risk_score;
        scoreBar.style.width = "0%";
        setTimeout(() => {
            scoreBar.style.width = data.risk_score + "%";
        }, 100);

        // Warning signs
        warningList.innerHTML = "";
        data.warning_signs.forEach((sign) => {
            const li = document.createElement("li");
            li.textContent = sign;
            warningList.appendChild(li);
        });

        // Safety advice
        adviceText.textContent = data.safety_advice;

        // Technical details
        modelPrediction.textContent = data.model_prediction || "Model not available";
        modelConfidence.textContent =
            data.model_confidence !== null
                ? (data.model_confidence * 100).toFixed(0) + "%"
                : "N/A";

        // Sources
        sourcesList.innerHTML = "";
        data.analysis_sources.forEach((src) => {
            const li = document.createElement("li");
            li.textContent = src;
            sourcesList.appendChild(li);
        });

        // Disclaimer
        resultDisclaimer.textContent = data.disclaimer;

        // Scroll to results
        resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // ---- Error display -------------------------------------------
    function showError(message) {
        resultsPanel.hidden = false;
        resultsPanel.className = "results-panel";
        resultsPanel.innerHTML =
            '<h2 class="panel-title">Analysis Error</h2>' +
            '<div class="error-message">' + message + "</div>";
    }

    // ---- Clear button --------------------------------------------
    clearBtn.addEventListener("click", () => {
        inputText.value = "";
        validateInput();
        resultsPanel.hidden = true;
        inputText.focus();
    });

    // ---- Technical details toggle --------------------------------
    detailsToggle.addEventListener("click", () => {
        detailsContent.classList.toggle("open");
        const arrow = detailsToggle.querySelector(".toggle-arrow");
        arrow.style.transform = detailsContent.classList.contains("open")
            ? "rotate(180deg)"
            : "rotate(0deg)";
    });

    // ---- Initialize ----------------------------------------------
    setMode("url");
})();

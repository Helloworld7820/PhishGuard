/**
 * PhishGuard Dashboard Visualizations Script
 * Renders Chart.js charts for Confusion Matrix & Feature Importances
 * using real evaluation metrics from reports/model_metrics.json.
 */
document.addEventListener("DOMContentLoaded", () => {
    const dataContainer = document.getElementById("chartDataContainer");
    if (!dataContainer) return;

    // 1. Confusion Matrix Breakdown Chart
    const tn = parseInt(dataContainer.dataset.cmTn || "0", 10);
    const fp = parseInt(dataContainer.dataset.cmFp || "0", 10);
    const fn = parseInt(dataContainer.dataset.cmFn || "0", 10);
    const tp = parseInt(dataContainer.dataset.cmTp || "0", 10);

    const confusionCanvas = document.getElementById("confusionChart");
    if (confusionCanvas) {
        new Chart(confusionCanvas, {
            type: "doughnut",
            data: {
                labels: [
                    "True Negative (Legit Correct)",
                    "False Positive (False Alarm)",
                    "False Negative (Phishing Missed)",
                    "True Positive (Phishing Caught)"
                ],
                datasets: [{
                    data: [tn, fp, fn, tp],
                    backgroundColor: [
                        "#10b981", // Emerald Green
                        "#f59e0b", // Amber Warning
                        "#ef4444", // Red Danger
                        "#00d2ff"  // Cyber Cyan
                    ],
                    borderColor: "#0a0f1d",
                    borderWidth: 2,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: "#111a33",
                        titleColor: "#00d2ff",
                        bodyColor: "#f8fafc",
                        borderColor: "#1e2d4d",
                        borderWidth: 1,
                        padding: 10
                    }
                },
                cutout: "68%"
            }
        });
    }

    // 2. Feature Importance Horizontal Bar Chart
    const rawFeatures = dataContainer.dataset.features;
    if (rawFeatures) {
        try {
            const features = JSON.parse(rawFeatures);
            // Display top 10 features for clean dashboard legibility
            const topFeatures = features.slice(0, 10);

            const labels = topFeatures.map((f) => f.feature);
            const values = topFeatures.map((f) => (f.importance * 100).toFixed(2));

            const featureCanvas = document.getElementById("featureImportanceChart");
            if (featureCanvas) {
                new Chart(featureCanvas, {
                    type: "bar",
                    data: {
                        labels: labels,
                        datasets: [{
                            label: "Relative Importance (%)",
                            data: values,
                            backgroundColor: "rgba(0, 210, 255, 0.7)",
                            hoverBackgroundColor: "#00d2ff",
                            borderColor: "#00d2ff",
                            borderWidth: 1,
                            borderRadius: 6
                        }]
                    },
                    options: {
                        indexAxis: "y",
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            },
                            tooltip: {
                                backgroundColor: "#111a33",
                                titleColor: "#00d2ff",
                                bodyColor: "#f8fafc",
                                borderColor: "#1e2d4d",
                                borderWidth: 1,
                                padding: 10,
                                callbacks: {
                                    label: (context) => ` Contribution: ${context.parsed.x}%`
                                }
                            }
                        },
                        scales: {
                            x: {
                                grid: {
                                    color: "rgba(30, 45, 77, 0.4)"
                                },
                                ticks: {
                                    color: "#94a3b8",
                                    font: { family: "JetBrains Mono", size: 11 }
                                }
                            },
                            y: {
                                grid: {
                                    display: false
                                },
                                ticks: {
                                    color: "#f8fafc",
                                    font: { family: "JetBrains Mono", size: 11 }
                                }
                            }
                        }
                    }
            }
        } catch (e) {
            console.error("Failed to parse feature importance metrics", e);
        }
    }

    // 3. Clear Scan History Handler
    const clearHistoryBtn = document.getElementById("clearHistoryBtn");
    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener("click", async () => {
            if (!confirm("Are you sure you want to clear your local scan history?")) {
                return;
            }
            try {
                const resp = await fetch("/api/history/clear", { method: "POST" });
                if (resp.ok) {
                    const tbody = document.getElementById("scanHistoryBody");
                    if (tbody) {
                        tbody.innerHTML = '<tr><td colspan="4" class="text-center py-3 text-muted-dim">Scan history cleared.</td></tr>';
                    }
                }
            } catch (err) {
                console.error("Failed to clear scan history:", err);
            }
        });
    }
});

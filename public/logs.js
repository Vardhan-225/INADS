document.addEventListener("DOMContentLoaded", function () {
  console.debug("📢 logs.js is LIVE!");

  fetch("/api/logs/all", { credentials: "include" })
    .then((response) => {
      console.debug(`🛰️ Response status: ${response.status}`);
      if (!response.ok) {
        throw new Error(`Failed to fetch logs. Status: ${response.status}`);
      }
      return response.json();
    })
    .then((data) => {
      console.debug("✅ Logs received from server. Total entries:", data.length);

      const tableBody = document.getElementById("logs-table-body");
      if (!tableBody) {
        console.error("❌ Element with ID 'logs-table-body' not found.");
        return;
      }

      tableBody.innerHTML = ""; // Clear previous data if any

      if (!Array.isArray(data) || data.length === 0) {
        tableBody.innerHTML = "<tr><td colspan='9'>No logs found.</td></tr>";
        return;
      }

      data.forEach((log) => {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${log.idx}</td>
          <td>${(log.global_conf * 100).toFixed(2)}%</td>
          <td>${(log.edge_conf * 100).toFixed(2)}%</td>
          <td>${(log.device_conf * 100).toFixed(2)}%</td>
          <td>${(log.fused_score * 100).toFixed(2)}%</td>
          <td><span class="badge ${log.label_pred === 1 ? 'bg-danger' : 'bg-success'}">
            ${log.label_pred === 1 ? "Attack" : "Benign"}
          </span></td>
          <td>${log.label_true === 1 ? "Attack" : "Benign"}</td>
          <td>${log.original_label || "-"}</td>
          <td>${new Date(log.detected_at).toLocaleString()}</td>
        `;
        tableBody.appendChild(row);
      });
    })
    .catch((error) => {
      console.error("❌ Error loading logs:", error.message || error);
      const tableBody = document.getElementById("logs-table-body");
      if (tableBody) {
        tableBody.innerHTML = `<tr><td colspan='9'>Error loading logs. (${error.message})</td></tr>`;
      }
    });
});
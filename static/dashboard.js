async function loadStats() {

    const token = localStorage.getItem("token");

    const response = await fetch("/security/stats", {
        headers: {
            "Authorization": "Bearer " + token
        }
    });

    const data = await response.json();

    document.getElementById("total").innerText = data.total_attempts;
    document.getElementById("failed").innerText = data.failed_attempts;
    document.getElementById("success").innerText = data.successful_logins;
    document.getElementById("blocked").innerText = data.active_blocked_ips;
    document.getElementById("locked").innerText = data.active_locked_accounts;
}

loadStats();
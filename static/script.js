async function login() {
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    const response = await fetch("/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (data.token) {
        localStorage.setItem("token", data.token);
        window.location.href = "/dashboard";
    } else {
        document.getElementById("message").innerText = data.error || data.message;
    }
}

async function loadStats() {
    const token = localStorage.getItem("token");

    if (!token) {
        window.location.href = "/";
        return;
    }

    const response = await fetch("/security/stats", {
        headers: {
            "Authorization": "Bearer " + token
        }
    });

    const data = await response.json();

    document.getElementById("stats").innerHTML = `
        <p>Total Attempts: ${data.total_attempts}</p>
        <p>Failed Attempts: ${data.failed_attempts}</p>
        <p>Successful Logins: ${data.successful_logins}</p>
        <p>Active Blocked IPs: ${data.active_blocked_ips}</p>
        <p>Active Locked Accounts: ${data.active_locked_accounts}</p>
    `;
}

function logout() {
    localStorage.removeItem("token");
    window.location.href = "/";
}

if (window.location.pathname === "/dashboard") {
    loadStats();
}
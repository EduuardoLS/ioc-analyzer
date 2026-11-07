async function executarAnalise() {
    const type = document.getElementById('iocType').value;
    const value = document.getElementById('iocInput').value.trim();

    if (!value) {
        alert('Por favor, informe um IOC válido para consulta.');
        return;
    }

    document.getElementById('displayTarget').innerText = value;
    document.getElementById('badgeRisk').className = "badge badge-neutral";
    document.getElementById('badgeRisk').innerText = "Consultando...";

    try {
        const response = await fetch('http://localhost:5000/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: type, value: value })
        });

        const data = await response.json();

        if (response.ok) {
            atualizarDashboard(value, data);
            adicionarHistorico(value, data.risk);
        } else {
            alert(data.error || "Erro ao consultar a API.");
            document.getElementById('badgeRisk').innerText = "Erro";
        }
    } catch (error) {
        console.error("Erro de conexão:", error);
        alert("Não foi possível conectar ao servidor backend Flask.");
    }
}

function atualizarDashboard(target, data) {
    const displayTarget = target.length > 40 ? target.substring(0, 20) + "..." + target.substring(target.length - 10) : target;
    
    document.getElementById('displayTarget').innerText = target;
    document.getElementById('tblTarget').innerText = displayTarget;
    document.getElementById('tblTarget').title = target;

    const stats = data.stats || {};
    document.getElementById('statMalicious').innerText = stats.malicious || 0;
    document.getElementById('statSuspicious').innerText = stats.suspicious || 0;
    document.getElementById('statHarmless').innerText = stats.harmless || 0;
    document.getElementById('statUndetected').innerText = stats.undetected || 0;

    document.getElementById('metaReputation').innerText = data.reputation || 0;
    document.getElementById('metaSeverity').innerText = data.risk;

    const badge = document.getElementById('badgeRisk');
    const tblRisk = document.getElementById('tblRisk');
    
    badge.innerText = data.risk;
    tblRisk.innerText = data.risk;

    if (data.risk.includes("Alto") || data.risk.includes("Malicioso")) {
        badge.className = "badge badge-danger";
        tblRisk.className = "badge badge-danger";
    } else if (data.risk.includes("Suspeito")) {
        badge.className = "badge badge-warning";
        tblRisk.className = "badge badge-warning";
    } else {
        badge.className = "badge badge-success";
        tblRisk.className = "badge badge-success";
    }
}

function adicionarHistorico(target, risk) {
    const list = document.getElementById('historyList');
    if (list.querySelector('.text-muted')) {
        list.innerHTML = '';
    }
    const item = document.createElement('li');
    item.className = 'history-item';
    item.innerText = `${target} (${risk})`;
    list.prepend(item);
}
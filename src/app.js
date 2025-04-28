document.addEventListener('DOMContentLoaded', () => {
  // Elementos do DOM
  const scanButton = document.getElementById('scan-button');
  const targetUrl = document.getElementById('target-url');
  const loadingIndicator = document.getElementById('loading-indicator');
  const resultsContainer = document.getElementById('results-container');
  const vulnerabilitiesList = document.getElementById('vulnerabilities-list');

  // Verificação de elementos
  if (!scanButton || !targetUrl || !loadingIndicator || !resultsContainer || !vulnerabilitiesList) {
    console.error('Erro: Elementos do DOM não encontrados. Verifique os IDs no HTML.');
    return;
  }

  scanButton.addEventListener('click', async () => {
    const url = targetUrl.value.trim();
    
    if (!url) {
      alert('Por favor, insira uma URL válida (ex: https://exemplo.com)');
      return;
    }

    // Mostra loading e esconde resultados
    loadingIndicator.style.display = 'flex';
    resultsContainer.style.display = 'none';
    vulnerabilitiesList.innerHTML = '';

    try {
      // Opções selecionadas pelo usuário
      const options = {
        sqli: document.getElementById('scan-sqli').checked,
        xss: document.getElementById('scan-xss').checked,
        csrf: document.getElementById('scan-csrf').checked,
        cors: document.getElementById('scan-cors').checked,
        headers: document.getElementById('scan-headers').checked
      };

      // Chama a Netlify Function
      const response = await fetch('/.netlify/functions/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url, options }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `Erro HTTP: ${response.status}`);
      }

      const data = await response.json();
      
      // Exibe os resultados
      displayResults(data);
      
    } catch (error) {
      vulnerabilitiesList.innerHTML = `
        <div class="error-message">
          <p>❌ Falha na análise: ${error.message}</p>
          <p>Tente novamente mais tarde.</p>
        </div>
      `;
    } finally {
      loadingIndicator.style.display = 'none';
      resultsContainer.style.display = 'block';
    }
  });

  function displayResults(data) {
    if (!data.success) {
      vulnerabilitiesList.innerHTML = `
        <div class="error-message">
          <p>❌ ${data.error || 'Erro desconhecido'}</p>
          ${data.details ? `<p>${data.details}</p>` : ''}
        </div>
      `;
      return;
    }

    // Atualiza contadores
    document.getElementById('count-high').textContent = data.results.high?.length || 0;
    document.getElementById('count-medium').textContent = data.results.medium?.length || 0;
    document.getElementById('count-low').textContent = data.results.low?.length || 0;
    document.getElementById('count-info').textContent = data.results.info?.length || 0;

    // Exibe vulnerabilidades
    const allVulnerabilities = [
      ...(data.results.high || []),
      ...(data.results.medium || []),
      ...(data.results.low || []),
      ...(data.results.info || [])
    ];

    if (allVulnerabilities.length === 0) {
      vulnerabilitiesList.innerHTML = `
        <div class="no-vulnerabilities">
          ✅ Nenhuma vulnerabilidade encontrada.
        </div>
      `;
      return;
    }

    allVulnerabilities.forEach(vuln => {
      const vulnElement = document.createElement('div');
      vulnElement.className = `vulnerability ${vuln.severity.toLowerCase()}`;
      vulnElement.innerHTML = `
        <h3>${vuln.type}</h3>
        <div class="meta">
          <span class="severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
          <span>${vuln.location}</span>
        </div>
        ${vuln.payload ? `<p><strong>Payload:</strong> <code>${vuln.payload}</code></p>` : ''}
        <p class="description">${vuln.description}</p>
      `;
      vulnerabilitiesList.appendChild(vulnElement);
    });
  }
});
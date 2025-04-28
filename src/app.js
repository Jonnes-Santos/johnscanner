document.addEventListener('DOMContentLoaded', () => {
    const scanButton = document.getElementById('scan-button');
    const targetUrl = document.getElementById('target-url');
    const vulnerabilitiesList = document.getElementById('vulnerabilities-list');
    const loadingIndicator = document.getElementById('loading-indicator');
    const resultsContainer = document.getElementById('results-container');
  
    // Esconde resultados inicialmente
    resultsContainer.style.display = 'none';
  
    scanButton.addEventListener('click', async () => {
      const url = targetUrl.value.trim();
      
      if (!url) {
        alert('Por favor, insira uma URL válida (ex: https://exemplo.com)');
        return;
      }
  
      // Mostra loading
      loadingIndicator.style.display = 'block';
      vulnerabilitiesList.innerHTML = '';
      resultsContainer.style.display = 'none';
  
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
          throw new Error(`Erro HTTP: ${response.status}`);
        }
  
        const data = await response.json();
  
        if (data.error) {
          throw new Error(data.error);
        }
  
        // Atualiza a UI com os resultados
        updateResultsUI(data);
        
      } catch (error) {
        vulnerabilitiesList.innerHTML = `
          <div class="error-message">
            <p>❌ Falha na análise: ${error.message}</p>
            <p>Tente novamente ou verifique a URL.</p>
          </div>
        `;
      } finally {
        loadingIndicator.style.display = 'none';
        resultsContainer.style.display = 'block';
      }
    });
  
    function updateResultsUI(data) {
      const vulnerabilities = [
        ...(data.results.high || []),
        ...(data.results.medium || []),
        ...(data.results.low || []),
        ...(data.results.info || [])
      ];
  
      // Atualiza contadores
      document.getElementById('count-high').textContent = data.results.high?.length || 0;
      document.getElementById('count-medium').textContent = data.results.medium?.length || 0;
      document.getElementById('count-low').textContent = data.results.low?.length || 0;
      document.getElementById('count-info').textContent = data.results.info?.length || 0;
  
      // Exibe vulnerabilidades
      if (vulnerabilities.length === 0) {
        vulnerabilitiesList.innerHTML = `
          <div class="no-vulnerabilities">
            ✅ Nenhuma vulnerabilidade encontrada.
          </div>
        `;
        return;
      }
  
      vulnerabilities.forEach(vuln => {
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
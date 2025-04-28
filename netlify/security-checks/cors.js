const axios = require('axios');

module.exports = async (url) => {
  const results = [];
  
  try {
    // Teste de CORS básico
    const testUrl = url.replace(/\/$/, '');
    const testOrigin = 'https://malicious.example.com';
    
    const response = await axios.get(testUrl, {
      headers: {
        'Origin': testOrigin
      },
      validateStatus: () => true // Aceita todos os status codes
    });
    
    const acao = response.headers['access-control-allow-origin'];
    const acac = response.headers['access-control-allow-credentials'];
    
    if (acao === '*' && acac === 'true') {
      results.push({
        type: "CORS Misconfiguration",
        severity: "High",
        location: "Headers",
        payload: `Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true`,
        description: "Configuração CORS permissiva permite acesso de qualquer origem com credenciais"
      });
    } else if (acao === '*') {
      results.push({
        type: "CORS Misconfiguration",
        severity: "Medium",
        location: "Headers",
        payload: `Access-Control-Allow-Origin: *`,
        description: "Configuração CORS permite acesso de qualquer origem"
      });
    } else if (acao === testOrigin) {
      results.push({
        type: "Reflected CORS Origin",
        severity: "High",
        location: "Headers",
        payload: `Access-Control-Allow-Origin: ${acao}`,
        description: "O servidor reflete a origem CORS, permitindo ataques CSRF entre origens"
      });
    }
    
    // Verifica métodos HTTP permitidos
    const acam = response.headers['access-control-allow-methods'];
    if (acam && acam.includes('DELETE') || acam.includes('PUT')) {
      results.push({
        type: "Permissive CORS Methods",
        severity: "Medium",
        location: "Headers",
        payload: `Access-Control-Allow-Methods: ${acam}`,
        description: "Métodos HTTP perigosos permitidos via CORS"
      });
    }
    
  } catch (error) {
    console.error("CORS check error:", error.message);
  }
  
  return results;
};
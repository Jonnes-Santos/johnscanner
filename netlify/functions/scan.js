const axios = require('axios');
const cheerio = require('cheerio');

// Módulos de verificação (simplificados para exemplo)
const securityChecks = {
  sqli: async (url, html) => {
    // Implementação real do SQLi check
    return []; // Retorna array de vulnerabilidades
  },
  xss: (html) => {
    // Implementação real do XSS check
    return [];
  },
  csrf: (html) => {
    // Implementação real do CSRF check
    return [];
  },
  cors: async (url) => {
    // Implementação real do CORS check
    return [];
  },
  headers: (headers) => {
    // Implementação real do Headers check
    return [];
  }
};

exports.handler = async (event) => {
  try {
    // Verifica o método HTTP
    if (event.httpMethod !== 'POST') {
      return {
        statusCode: 405,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Método não permitido' })
      };
    }

    const { url, options } = JSON.parse(event.body);

    // Validação da URL
    if (!url || !url.startsWith('http')) {
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'URL inválida. Use http:// ou https://' })
      };
    }

    // Faz a requisição HTTP
    const response = await axios.get(url, {
      headers: { 'User-Agent': 'SecurityScanner/1.0' },
      timeout: 10000,
    });

    const html = response.data;
    const headers = response.headers;

    // Executa verificações selecionadas
    const vulnerabilities = [];
    
    for (const [checkName, isEnabled] of Object.entries(options)) {
      if (isEnabled && securityChecks[checkName]) {
        const checkResults = await securityChecks[checkName](url, html, headers);
        vulnerabilities.push(...checkResults);
      }
    }

    // Classifica por severidade
    const results = {
      high: vulnerabilities.filter(v => v.severity === 'High'),
      medium: vulnerabilities.filter(v => v.severity === 'Medium'),
      low: vulnerabilities.filter(v => v.severity === 'Low'),
      info: vulnerabilities.filter(v => v.severity === 'Info'),
    };

    // Retorno de sucesso
    return {
      statusCode: 200,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*' 
      },
      body: JSON.stringify({
        success: true,
        url,
        results,
        total: vulnerabilities.length
      })
    };

  } catch (error) {
    // Tratamento de erros
    return {
      statusCode: 500,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*' 
      },
      body: JSON.stringify({
        success: false,
        error: 'Falha na análise',
        details: error.message
      })
    };
  }
};
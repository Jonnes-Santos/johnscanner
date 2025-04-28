const axios = require('axios');
const cheerio = require('cheerio');

// Importa todos os módulos de verificação
const sqliCheck = require('./security-checks/sqli');
const xssCheck = require('./security-checks/xss');
const csrfCheck = require('./security-checks/csrf');
const corsCheck = require('./security-checks/cors');
const headersCheck = require('./security-checks/headers');

exports.handler = async (event) => {
  try {
    // Verifica se é uma requisição POST
    if (event.httpMethod !== 'POST') {
      return {
        statusCode: 405,
        body: JSON.stringify({ error: 'Método não permitido' }),
      };
    }

    const { url, options } = JSON.parse(event.body);

    // Valida a URL
    if (!url || !url.startsWith('http')) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'URL inválida. Use http:// ou https://' }),
      };
    }

    // Faz a requisição HTTP
    const response = await axios.get(url, {
      headers: { 'User-Agent': 'SecurityScanner/1.0' },
      timeout: 10000,
    });

    const html = response.data;
    const $ = cheerio.load(html);
    const headers = response.headers;

    // Executa verificações com base nas opções
    const vulnerabilities = [];

    if (options.sqli) vulnerabilities.push(...await sqliCheck(url, html));
    if (options.xss) vulnerabilities.push(...xssCheck(html));
    if (options.csrf) vulnerabilities.push(...csrfCheck(html));
    if (options.cors) vulnerabilities.push(...await corsCheck(url));
    if (options.headers) vulnerabilities.push(...headersCheck(headers));

    // Classifica por severidade
    const results = {
      high: vulnerabilities.filter(v => v.severity === 'High'),
      medium: vulnerabilities.filter(v => v.severity === 'Medium'),
      low: vulnerabilities.filter(v => v.severity === 'Low'),
      info: vulnerabilities.filter(v => v.severity === 'Info'),
    };

    // Retorna os resultados
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify({
        success: true,
        url,
        results,
        total: vulnerabilities.length,
      }),
    };

  } catch (error) {
    // Tratamento de erros
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify({
        success: false,
        error: 'Falha na análise',
        details: error.message,
      }),
    };
  }
};
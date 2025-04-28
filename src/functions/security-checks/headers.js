module.exports = (headers) => {
    const results = [];
    const securityHeaders = [
      {
        name: 'Strict-Transport-Security',
        description: 'Força conexões HTTPS',
        required: true,
        severity: 'High'
      },
      {
        name: 'X-Frame-Options',
        description: 'Prevenção contra clickjacking',
        required: true,
        severity: 'High'
      },
      {
        name: 'X-Content-Type-Options',
        description: 'Previne MIME sniffing',
        required: true,
        severity: 'Medium'
      },
      {
        name: 'Content-Security-Policy',
        description: 'Política de segurança de conteúdo',
        required: false,
        severity: 'High'
      },
      {
        name: 'Referrer-Policy',
        description: 'Controle de informação de referência',
        required: false,
        severity: 'Low'
      }
    ];
  
    // Verifica headers de segurança ausentes
    securityHeaders.forEach(header => {
      if (header.required && !headers[header.name.toLowerCase()]) {
        results.push({
          type: "Missing Security Header",
          severity: header.severity,
          location: "Response Headers",
          payload: header.name,
          description: `${header.description} - Este header de segurança está ausente`
        });
      }
    });
  
    // Verifica valores inseguros em headers existentes
    if (headers['x-frame-options'] && headers['x-frame-options'].toLowerCase() === 'allow-from') {
      results.push({
        type: "Insecure X-Frame-Options",
        severity: "Medium",
        location: "Response Headers",
        payload: headers['x-frame-options'],
        description: "X-Frame-Options 'allow-from' é considerado inseguro, use 'DENY' ou 'SAMEORIGIN'"
      });
    }
  
    if (headers['strict-transport-security'] && !headers['strict-transport-security'].includes('max-age')) {
      results.push({
        type: "Incomplete HSTS Policy",
        severity: "High",
        location: "Response Headers",
        payload: headers['strict-transport-security'],
        description: "Header HSTS deve incluir 'max-age' directive"
      });
    }
  
    return results;
  };
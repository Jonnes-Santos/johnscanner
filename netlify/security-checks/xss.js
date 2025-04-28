module.exports = (html) => {
    const xssPatterns = [
      /<script>alert\(.*\)<\/script>/i,
      /onerror=.*?\(.*?\)/i,
      /javascript:/i
    ];
  
    const results = [];
    
    xssPatterns.forEach(pattern => {
      if (pattern.test(html)) {
        results.push({
          type: "Cross-Site Scripting (XSS)",
          severity: "High",
          location: "HTML content",
          payload: "Padrão XSS detectado: " + pattern.toString(),
          description: "Possível vulnerabilidade XSS detectada no código"
        });
      }
    });
  
    return results;
  };
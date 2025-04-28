module.exports = (html) => {
    const results = [];
    const forms = extractForms(html);
  
    forms.forEach(form => {
      if (!form.hasCSRFToken) {
        results.push({
          type: "Missing CSRF Protection",
          severity: "Medium",
          location: form.action,
          payload: "Faltando token CSRF",
          description: "Formulário sem proteção contra CSRF"
        });
      }
    });
  
    return results;
  };
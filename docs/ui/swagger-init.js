(function () {
  "use strict";
  function launch() {
    const root = document.querySelector('#swagger-ui');
    if (!window.SwaggerUIBundle) {
      root.textContent = 'Swagger UI não carregou (CDN indisponível). Use a interface offline pelo link acima.';
      return;
    }
    window.SwaggerUIBundle({
      url: '/openapi.json',
      dom_id: '#swagger-ui',
      deepLinking: true,
      presets: [window.SwaggerUIBundle.presets.apis],
      layout: 'BaseLayout',
      validatorUrl: null,
      tryItOutEnabled: false,
      supportedSubmitMethods: ['get', 'post', 'put', 'patch', 'delete'],
      requestInterceptor: function (req) {
        const target = new URL(req.url, window.location.href);
        if (target.origin === window.location.origin && (target.pathname === '/api/v1/users' || target.pathname.startsWith('/api/v1/users/') || ['/api/v1/auth/login', '/api/v1/auth/me', '/api/v1/auth/logout'].includes(target.pathname))) {
          req.headers = req.headers || {};
          req.headers['X-Lab-Token'] = document.querySelector('meta[name="lab-token"]').content;
        }
        return req;
      }
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', launch);
  else launch();
}());

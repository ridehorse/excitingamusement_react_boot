const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app){
 
  app.use('/api',
    createProxyMiddleware('/localhost', {
      target: 'localhost:8080',
      pathRewrite: {
        '^/localhost:8080/':''
      },
      changeOrigin: true
    })
  )

};
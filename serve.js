'use strict';

const { loadVaultSecrets } = require('./config/vault');

function createApp() {
  const express = require('express');
  const cors = require('cors');
  const bodyParser = require('body-parser');
  const db = require('./src/models');

  const app = express();
  const corsOptions = {
    origin: '*',
  };

  app.use(cors(corsOptions));
  db.sequelize.sync();
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use('/static', express.static('assets'));

  require('./src/routes')(app);

  return app;
}

async function startServer() {
  await loadVaultSecrets();

  const app = createApp();
  const port = process.env.PORT || 8000;

  return new Promise((resolve, reject) => {
    const server = app.listen(port, '0.0.0.0', () => {
      console.log(`App listening on port ${port}`);
      resolve({ app, server });
    });

    server.on('error', reject);
  });
}

if (require.main === module) {
  startServer().catch((error) => {
    console.error(`[startup] ${error.message}`);
    if (error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  });
}

module.exports = {
  createApp,
  startServer,
};
'use strict';

const { spawn } = require('child_process');
const { loadVaultSecrets } = require('../config/vault');

async function main() {
  const command = process.argv[2];
  const args = process.argv.slice(3);

  if (!command) {
    console.error('Usage: node scripts/withVault.js <command> [args...]');
    process.exit(1);
  }

  await loadVaultSecrets();

  const child = spawn(command, args, {
    cwd: process.cwd(),
    env: process.env,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });

  child.on('error', (error) => {
    console.error(`[vault] Impossible de lancer la commande: ${error.message}`);
    process.exit(1);
  });

  child.on('exit', (code) => {
    process.exit(code ?? 1);
  });
}

main().catch((error) => {
  console.error(`[vault] ${error.message}`);
  if (error.stack) {
    console.error(error.stack);
  }
  process.exit(1);
});
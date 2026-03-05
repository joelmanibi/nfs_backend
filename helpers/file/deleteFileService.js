// deleteFileService.js
const fs = require('fs');
const path = require('path');

// Fonction pour supprimer un fichier
const deleteFile = (filePath) => {
  return new Promise((resolve, reject) => {
    fs.access(filePath, fs.constants.F_OK, (err) => {
      if (err) {
        // Si le fichier n'existe pas, continuer sans erreur
        console.warn(`Le fichier ${filePath} n'existe pas.`);
        return resolve(false);
      }
      // Supprimer le fichier
      fs.unlink(filePath, (err) => {
        if (err) {
          return reject(err);
        }
        resolve(true);
      });
    });
  });
};

module.exports = deleteFile;

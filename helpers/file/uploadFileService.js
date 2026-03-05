const multer = require('multer');
const uniqid = require('uniqid');
const path = require('path');
const fs = require('fs');

// Fonction pour créer des dossiers s'ils n'existent pas
const ensureDirectoryExistence = (filePath) => {
  const dirname = path.dirname(filePath);
  if (fs.existsSync(dirname)) {
    return true;
  }
  fs.mkdirSync(dirname, { recursive: true });
};

// Validation des types de fichiers
const fileFilter = (req, file, cb) => {
  // Types de fichiers autorisés
  const allowedTypes = [
    'application/pdf', 
    'application/msword', 
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'image/jpeg',
    'image/png'
  ];
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Type de fichier non autorisé. Seuls PDF, Word, Excel et images sont acceptés.'), false);
  }
};

// Configuration du stockage pour multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let uploadPath = 'assets/';

    if (file.fieldname === 'rfcDocuments') {
      uploadPath += 'rfcDoc/';
    } else {
      uploadPath += 'others/';
    }

    ensureDirectoryExistence(uploadPath);
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    // Génération d'un nom de fichier unique
    const uniqueName = Date.now() + uniqid() + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

// Initialiser multer avec la configuration de stockage et des limites
const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max
    files: 10 // Maximum 10 fichiers
  }
});

module.exports = upload;

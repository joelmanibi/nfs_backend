'use strict';

const { Router } = require('express');
const { verifyToken } = require('../middleware/authMiddleware');
const { checkRole } = require('../middleware/roleMiddleware');
const {
  listCollectionConfigs,
  getCollectionConfig,
  createCollectionConfig,
  updateCollectionConfig,
  deleteCollectionConfig,
  runCollectionConfig,
  getCollectionExecutions,
} = require('../controllers/adminCollectionController');

const router = Router();

router.use(verifyToken, checkRole('ADMIN', 'SUPER_ADMIN'));

router.get('/', listCollectionConfigs);
router.post('/', createCollectionConfig);
router.get('/:id', getCollectionConfig);
router.patch('/:id', updateCollectionConfig);
router.delete('/:id', deleteCollectionConfig);
router.post('/:id/run', runCollectionConfig);
router.get('/:id/executions', getCollectionExecutions);

module.exports = router;
'use strict';

const { Sequelize } = require('sequelize');
const dbConfig = require('../../config/database');

const env = process.env.NODE_ENV || 'development';
const config = dbConfig[env];

const sequelize = new Sequelize(
  config.database,
  config.username,
  config.password,
  config,
);

// --- Model imports ---
const User      = require('./User')(sequelize, Sequelize.DataTypes);
const OTP       = require('./OTP')(sequelize, Sequelize.DataTypes);
const File      = require('./File')(sequelize, Sequelize.DataTypes);
const ShareLink = require('./ShareLink')(sequelize, Sequelize.DataTypes);
const DownloadLog = require('./DownloadLog')(sequelize, Sequelize.DataTypes);
const CollectionConfig = require('./CollectionConfig')(sequelize, Sequelize.DataTypes);
const CollectionRecipient = require('./CollectionRecipient')(sequelize, Sequelize.DataTypes);
const CollectionExecution = require('./CollectionExecution')(sequelize, Sequelize.DataTypes);

// --- Associations ---
User.hasMany(File, { foreignKey: 'senderId', as: 'sentFiles' });
File.belongsTo(User, { foreignKey: 'senderId', as: 'sender' });

File.hasMany(ShareLink, { foreignKey: 'fileId', as: 'shareLinks', onDelete: 'CASCADE' });
ShareLink.belongsTo(File, { foreignKey: 'fileId', as: 'file' });

File.hasMany(DownloadLog, { foreignKey: 'fileId', as: 'downloadLogs', onDelete: 'CASCADE' });
DownloadLog.belongsTo(File, { foreignKey: 'fileId', as: 'file' });

User.hasMany(CollectionConfig, { foreignKey: 'createdByAdminId', as: 'collectionConfigs' });
CollectionConfig.belongsTo(User, { foreignKey: 'createdByAdminId', as: 'createdBy' });

CollectionConfig.hasMany(CollectionRecipient, { foreignKey: 'collectionConfigId', as: 'recipients', onDelete: 'CASCADE' });
CollectionRecipient.belongsTo(CollectionConfig, { foreignKey: 'collectionConfigId', as: 'collectionConfig' });
CollectionRecipient.belongsTo(User, { foreignKey: 'userId', as: 'user' });
User.hasMany(CollectionRecipient, { foreignKey: 'userId', as: 'collectionRecipientLinks' });

CollectionConfig.hasMany(CollectionExecution, { foreignKey: 'collectionConfigId', as: 'executions', onDelete: 'CASCADE' });
CollectionExecution.belongsTo(CollectionConfig, { foreignKey: 'collectionConfigId', as: 'collectionConfig' });

const db = {
  sequelize,
  Sequelize,
  User,
  OTP,
  File,
  ShareLink,
  DownloadLog,
  CollectionConfig,
  CollectionRecipient,
  CollectionExecution,
};

module.exports = db;


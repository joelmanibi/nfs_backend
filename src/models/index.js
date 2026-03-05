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
const User = require('./User')(sequelize, Sequelize.DataTypes);
const OTP  = require('./OTP')(sequelize, Sequelize.DataTypes);
const File = require('./File')(sequelize, Sequelize.DataTypes);

// --- Associations ---
User.hasMany(File, { foreignKey: 'senderId', as: 'sentFiles' });
File.belongsTo(User, { foreignKey: 'senderId', as: 'sender' });

const db = {
  sequelize,
  Sequelize,
  User,
  OTP,
  File,
};

module.exports = db;


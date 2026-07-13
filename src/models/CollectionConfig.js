'use strict';

const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class CollectionConfig extends Model {}

  CollectionConfig.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      name: {
        type: DataTypes.STRING(150),
        allowNull: false,
      },
      host: {
        type: DataTypes.STRING(255),
        allowNull: false,
      },
      protocol: {
        type: DataTypes.ENUM('SFTP', 'FTP', 'FTPS', 'HTTP', 'HTTPS'),
        allowNull: false,
      },
      port: {
        type: DataTypes.INTEGER,
        allowNull: false,
      },
      username: {
        type: DataTypes.STRING(255),
        allowNull: false,
      },
      authType: {
        type: DataTypes.ENUM('PASSWORD', 'SSH_KEY'),
        allowNull: false,
        defaultValue: 'PASSWORD',
      },
      encryptedPassword: {
        type: DataTypes.TEXT('long'),
        allowNull: true,
        defaultValue: null,
      },
      encryptedPrivateKey: {
        type: DataTypes.TEXT('long'),
        allowNull: true,
        defaultValue: null,
      },
      sourceDirectory: {
        type: DataTypes.STRING(500),
        allowNull: false,
      },
      requestQuery: {
        type: DataTypes.TEXT,
        allowNull: true,
        defaultValue: null,
      },
      httpMethod: {
        type: DataTypes.ENUM('GET', 'POST'),
        allowNull: true,
        defaultValue: null,
      },
      httpHeaders: {
        type: DataTypes.TEXT('long'),
        allowNull: true,
        defaultValue: null,
      },
      httpBody: {
        type: DataTypes.TEXT('long'),
        allowNull: true,
        defaultValue: null,
      },
      httpResponseMode: {
        type: DataTypes.ENUM('SINGLE_FILE', 'FILE_LIST'),
        allowNull: true,
        defaultValue: null,
      },
      scheduleType: {
        type: DataTypes.ENUM('MANUAL', 'DAILY', 'WEEKLY', 'MONTHLY'),
        allowNull: false,
        defaultValue: 'MANUAL',
      },
      scheduleTime: {
        type: DataTypes.STRING(5),
        allowNull: true,
        defaultValue: null,
      },
      scheduleDayOfWeek: {
        type: DataTypes.INTEGER,
        allowNull: true,
        defaultValue: null,
      },
      scheduleDayOfMonth: {
        type: DataTypes.INTEGER,
        allowNull: true,
        defaultValue: null,
      },
      comment: {
        type: DataTypes.TEXT,
        allowNull: true,
        defaultValue: null,
      },
      description: {
        type: DataTypes.TEXT,
        allowNull: true,
        defaultValue: null,
      },
      isActive: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: true,
      },
      createdByAdminId: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      lastRunAt: {
        type: DataTypes.DATE,
        allowNull: true,
        defaultValue: null,
      },
      lastSuccessfulRunAt: {
        type: DataTypes.DATE,
        allowNull: true,
        defaultValue: null,
      },
      lastScheduledRunAt: {
        type: DataTypes.DATE,
        allowNull: true,
        defaultValue: null,
      },
    },
    {
      sequelize,
      modelName: 'CollectionConfig',
      tableName: 'collection_configs',
      timestamps: true,
    },
  );

  return CollectionConfig;
};
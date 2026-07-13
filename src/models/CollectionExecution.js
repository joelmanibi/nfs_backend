'use strict';

const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class CollectionExecution extends Model {}

  CollectionExecution.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      collectionConfigId: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      triggerType: {
        type: DataTypes.ENUM('MANUAL', 'SCHEDULED'),
        allowNull: false,
      },
      status: {
        type: DataTypes.ENUM('RUNNING', 'SUCCESS', 'PARTIAL', 'FAILED'),
        allowNull: false,
        defaultValue: 'RUNNING',
      },
      executedAt: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW,
      },
      finishedAt: {
        type: DataTypes.DATE,
        allowNull: true,
        defaultValue: null,
      },
      collectedFilesCount: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0,
      },
      distributedFilesCount: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0,
      },
      errorMessage: {
        type: DataTypes.TEXT,
        allowNull: true,
        defaultValue: null,
      },
    },
    {
      sequelize,
      modelName: 'CollectionExecution',
      tableName: 'collection_executions',
      timestamps: true,
    },
  );

  return CollectionExecution;
};
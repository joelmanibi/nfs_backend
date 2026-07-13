'use strict';

const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class DownloadLog extends Model {}

  DownloadLog.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      fileId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: { model: 'files', key: 'id' },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE',
      },
      downloadedBy: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      method: {
        type: DataTypes.ENUM('direct', 'link'),
        allowNull: false,
      },
      ip: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      userAgent: {
        type: DataTypes.STRING(500),
        allowNull: true,
      },
    },
    {
      sequelize,
      modelName: 'DownloadLog',
      tableName: 'download_logs',
      timestamps: true,
      updatedAt: false,
    },
  );

  return DownloadLog;
};

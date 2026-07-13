'use strict';

const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class File extends Model {
    static associate(models) {
      File.belongsTo(models.User, { foreignKey: 'senderId', as: 'sender' });
    }
  }

  File.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      reference: {
        type: DataTypes.STRING(40),
        allowNull: true,
        unique: true,
      },
      senderId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: { model: 'users', key: 'id' },
        onUpdate: 'CASCADE',
        onDelete: 'RESTRICT',
      },
      receiverEmail: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: { isEmail: true },
      },
      originalName: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      encryptedPath: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      size: {
        type: DataTypes.BIGINT,
        allowNull: false,
      },
      isProtected: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      isBlocked: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      status: {
        type: DataTypes.ENUM('pending_scan', 'clean', 'infected', 'scan_failed'),
        allowNull: false,
        defaultValue: 'clean',
      },
      downloadCodeHash: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      iv: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      comment: {
        type: DataTypes.TEXT,
        allowNull: true,
        defaultValue: null,
      },
      downloadedAt: {
        type: DataTypes.DATE,
        allowNull: true,
        defaultValue: null,
      },
      downloadedBy: {
        type: DataTypes.STRING,
        allowNull: true,
        defaultValue: null,
      },
    },
    {
      sequelize,
      modelName: 'File',
      tableName: 'files',
      timestamps: true,
      updatedAt: true,
    },
  );

  return File;
};


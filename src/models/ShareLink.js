'use strict';

const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class ShareLink extends Model {}

  ShareLink.init(
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
      token: {
        type: DataTypes.STRING(64),
        allowNull: false,
        unique: true,
      },
      expiresAt: {
        type: DataTypes.DATE,
        allowNull: false,
      },
    },
    {
      sequelize,
      modelName: 'ShareLink',
      tableName: 'share_links',
      timestamps: true,
      updatedAt: false,
    },
  );

  return ShareLink;
};


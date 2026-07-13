'use strict';

const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class CollectionRecipient extends Model {}

  CollectionRecipient.init(
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
      userId: {
        type: DataTypes.UUID,
        allowNull: false,
      },
    },
    {
      sequelize,
      modelName: 'CollectionRecipient',
      tableName: 'collection_recipients',
      timestamps: true,
      indexes: [
        {
          unique: true,
          fields: ['collectionConfigId', 'userId'],
        },
      ],
    },
  );

  return CollectionRecipient;
};
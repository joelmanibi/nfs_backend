'use strict';

const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class OTP extends Model {}

  OTP.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: { isEmail: true },
      },
      otpHash: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      expiresAt: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      attempts: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0,
      },
    },
    {
      sequelize,
      modelName: 'OTP',
      tableName: 'otps',
      timestamps: true,
      updatedAt: false,
    },
  );

  return OTP;
};


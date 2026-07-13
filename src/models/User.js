'use strict';

const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    static associate(models) {
      User.hasMany(models.File, { foreignKey: 'senderId', as: 'sentFiles' });
    }
  }

  User.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      firstName: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      lastName: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      phone: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      organisation: {
        type: DataTypes.STRING(255),
        allowNull: true,
        defaultValue: null,
      },
      country: {
        type: DataTypes.STRING(100),
        allowNull: true,
        defaultValue: null,
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: { isEmail: true },
      },
      city: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      role: {
        type: DataTypes.ENUM('SUPER_ADMIN', 'ADMIN', 'USER'),
        allowNull: false,
        defaultValue: 'USER',
      },
      passwordHash: {
        type: DataTypes.STRING(255),
        allowNull: true,
        defaultValue: null,
      },
      resetTokenHash: {
        type: DataTypes.STRING(255),
        allowNull: true,
        defaultValue: null,
      },
      resetTokenExpiresAt: {
        type: DataTypes.DATE,
        allowNull: true,
        defaultValue: null,
      },
      isInternalUser: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      isApproved: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      mustChangePassword: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      isBlocked: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
    },
    {
      sequelize,
      modelName: 'User',
      tableName: 'users',
      timestamps: true,
    },
  );

  return User;
};


'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('collection_configs', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      name: {
        type: Sequelize.STRING(150),
        allowNull: false,
      },
      host: {
        type: Sequelize.STRING(255),
        allowNull: false,
      },
      protocol: {
        type: Sequelize.ENUM('SFTP', 'FTP', 'FTPS'),
        allowNull: false,
      },
      port: {
        type: Sequelize.INTEGER,
        allowNull: false,
      },
      username: {
        type: Sequelize.STRING(255),
        allowNull: false,
      },
      authType: {
        type: Sequelize.ENUM('PASSWORD', 'SSH_KEY'),
        allowNull: false,
        defaultValue: 'PASSWORD',
      },
      encryptedPassword: {
        type: Sequelize.TEXT('long'),
        allowNull: true,
        defaultValue: null,
      },
      encryptedPrivateKey: {
        type: Sequelize.TEXT('long'),
        allowNull: true,
        defaultValue: null,
      },
      sourceDirectory: {
        type: Sequelize.STRING(500),
        allowNull: false,
      },
      scheduleType: {
        type: Sequelize.ENUM('MANUAL', 'DAILY', 'WEEKLY', 'MONTHLY'),
        allowNull: false,
        defaultValue: 'MANUAL',
      },
      scheduleTime: {
        type: Sequelize.STRING(5),
        allowNull: true,
        defaultValue: null,
      },
      scheduleDayOfWeek: {
        type: Sequelize.INTEGER,
        allowNull: true,
        defaultValue: null,
      },
      scheduleDayOfMonth: {
        type: Sequelize.INTEGER,
        allowNull: true,
        defaultValue: null,
      },
      comment: {
        type: Sequelize.TEXT,
        allowNull: true,
        defaultValue: null,
      },
      description: {
        type: Sequelize.TEXT,
        allowNull: true,
        defaultValue: null,
      },
      isActive: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: true,
      },
      createdByAdminId: {
        type: Sequelize.UUID,
        allowNull: false,
        references: { model: 'users', key: 'id' },
        onUpdate: 'CASCADE',
        onDelete: 'RESTRICT',
      },
      lastRunAt: {
        type: Sequelize.DATE,
        allowNull: true,
        defaultValue: null,
      },
      lastSuccessfulRunAt: {
        type: Sequelize.DATE,
        allowNull: true,
        defaultValue: null,
      },
      lastScheduledRunAt: {
        type: Sequelize.DATE,
        allowNull: true,
        defaultValue: null,
      },
      createdAt: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.NOW,
      },
      updatedAt: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.NOW,
      },
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('collection_configs');
  },
};
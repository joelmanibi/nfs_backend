'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('collection_executions', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      collectionConfigId: {
        type: Sequelize.UUID,
        allowNull: false,
        references: { model: 'collection_configs', key: 'id' },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE',
      },
      triggerType: {
        type: Sequelize.ENUM('MANUAL', 'SCHEDULED'),
        allowNull: false,
      },
      status: {
        type: Sequelize.ENUM('RUNNING', 'SUCCESS', 'PARTIAL', 'FAILED'),
        allowNull: false,
        defaultValue: 'RUNNING',
      },
      executedAt: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.NOW,
      },
      finishedAt: {
        type: Sequelize.DATE,
        allowNull: true,
        defaultValue: null,
      },
      collectedFilesCount: {
        type: Sequelize.INTEGER,
        allowNull: false,
        defaultValue: 0,
      },
      distributedFilesCount: {
        type: Sequelize.INTEGER,
        allowNull: false,
        defaultValue: 0,
      },
      errorMessage: {
        type: Sequelize.TEXT,
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

    await queryInterface.addIndex('collection_executions', ['collectionConfigId', 'executedAt'], {
      name: 'collection_executions_config_executed_at_idx',
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('collection_executions');
  },
};
'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('download_logs', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      fileId: {
        type: Sequelize.UUID,
        allowNull: false,
        references: { model: 'files', key: 'id' },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE',
      },
      downloadedBy: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      method: {
        type: Sequelize.ENUM('direct', 'link'),
        allowNull: false,
      },
      ip: {
        type: Sequelize.STRING,
        allowNull: true,
      },
      userAgent: {
        type: Sequelize.STRING(500),
        allowNull: true,
      },
      createdAt: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.NOW,
      },
    });

    await queryInterface.addIndex('download_logs', ['fileId'], { name: 'download_logs_file_id_idx' });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('download_logs');
  },
};

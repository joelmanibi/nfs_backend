'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('files', 'status', {
      type: Sequelize.ENUM('pending_scan', 'clean', 'infected', 'scan_failed'),
      allowNull: false,
      defaultValue: 'clean',
      after: 'isBlocked',
    });
    await queryInterface.addIndex('files', ['status'], { name: 'files_status_idx' });
  },

  async down(queryInterface) {
    await queryInterface.removeIndex('files', 'files_status_idx');
    await queryInterface.removeColumn('files', 'status');
  },
};

'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('files', 'isBlocked', {
      type: Sequelize.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      after: 'isProtected',
    });
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('files', 'isBlocked');
  },
};


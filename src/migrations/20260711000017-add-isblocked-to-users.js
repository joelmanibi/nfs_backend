'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('users', 'isBlocked', {
      type: Sequelize.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      after: 'mustChangePassword',
    });
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('users', 'isBlocked');
  },
};

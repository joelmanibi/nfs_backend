'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('users', 'mustChangePassword', {
      type: Sequelize.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      after: 'isApproved',
    });
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('users', 'mustChangePassword');
  },
};

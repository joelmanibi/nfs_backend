'use strict';

// Suppression logique des comptes (Sequelize paranoid) : la ligne reste en
// base avec sa date de suppression, ce qui permet une restauration ultérieure.
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('users', 'deletedAt', {
      type: Sequelize.DATE,
      allowNull: true,
      defaultValue: null,
      after: 'isBlocked',
    });
    await queryInterface.addColumn('users', 'deletedById', {
      type: Sequelize.UUID,
      allowNull: true,
      defaultValue: null,
      after: 'deletedAt',
    });
    await queryInterface.addIndex('users', ['deletedAt'], { name: 'users_deleted_at' });
  },

  async down(queryInterface) {
    await queryInterface.removeIndex('users', 'users_deleted_at');
    await queryInterface.removeColumn('users', 'deletedById');
    await queryInterface.removeColumn('users', 'deletedAt');
  },
};

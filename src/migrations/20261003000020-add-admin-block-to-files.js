'use strict';

// Blocage d'un fichier par un administrateur, distinct de isBlocked (posé par
// l'expéditeur) : l'expéditeur ne peut pas le lever. adminBlockedAt non nul
// = fichier bloqué, avec la date et l'auteur du blocage.
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('files', 'adminBlockedAt', {
      type: Sequelize.DATE,
      allowNull: true,
      defaultValue: null,
      after: 'isBlocked',
    });
    await queryInterface.addColumn('files', 'adminBlockedById', {
      type: Sequelize.UUID,
      allowNull: true,
      defaultValue: null,
      after: 'adminBlockedAt',
    });
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('files', 'adminBlockedById');
    await queryInterface.removeColumn('files', 'adminBlockedAt');
  },
};

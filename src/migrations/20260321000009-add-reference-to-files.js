'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('files', 'reference', {
      type: Sequelize.STRING(40),
      allowNull: true,       // nullable pour les anciens enregistrements
      unique: true,
      after: 'id',           // juste après la PK (MySQL / MariaDB)
    });
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('files', 'reference');
  },
};


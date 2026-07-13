'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('collection_configs', 'httpMethod', {
      type: Sequelize.ENUM('GET', 'POST'),
      allowNull: true,
      defaultValue: null,
    });

    await queryInterface.addColumn('collection_configs', 'httpHeaders', {
      type: Sequelize.TEXT('long'),
      allowNull: true,
      defaultValue: null,
    });

    await queryInterface.addColumn('collection_configs', 'httpBody', {
      type: Sequelize.TEXT('long'),
      allowNull: true,
      defaultValue: null,
    });

    await queryInterface.addColumn('collection_configs', 'httpResponseMode', {
      type: Sequelize.ENUM('SINGLE_FILE', 'FILE_LIST'),
      allowNull: true,
      defaultValue: null,
    });
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('collection_configs', 'httpResponseMode');
    await queryInterface.removeColumn('collection_configs', 'httpBody');
    await queryInterface.removeColumn('collection_configs', 'httpHeaders');
    await queryInterface.removeColumn('collection_configs', 'httpMethod');
  },
};
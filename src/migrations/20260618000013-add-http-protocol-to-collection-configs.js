'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.changeColumn('collection_configs', 'protocol', {
      type: Sequelize.ENUM('SFTP', 'FTP', 'FTPS', 'HTTP', 'HTTPS'),
      allowNull: false,
    });

    await queryInterface.addColumn('collection_configs', 'requestQuery', {
      type: Sequelize.TEXT,
      allowNull: true,
      defaultValue: null,
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.removeColumn('collection_configs', 'requestQuery');

    await queryInterface.changeColumn('collection_configs', 'protocol', {
      type: Sequelize.ENUM('SFTP', 'FTP', 'FTPS'),
      allowNull: false,
    });
  },
};
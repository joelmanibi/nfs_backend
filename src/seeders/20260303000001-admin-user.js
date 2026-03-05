'use strict';

require('dotenv').config();
const { v4: uuidv4 } = require('uuid');

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface) {
    const email = process.env.ADMIN_EMAIL;

    if (!email) {
      throw new Error('ADMIN_EMAIL is not defined in environment variables.');
    }

    const [existing] = await queryInterface.sequelize.query(
      `SELECT id FROM users WHERE email = :email LIMIT 1`,
      { replacements: { email }, type: queryInterface.sequelize.QueryTypes.SELECT },
    );

    if (existing) {
      console.log(`[seeder] Admin user already exists (${email}). Skipping.`);
      return;
    }

    await queryInterface.bulkInsert('users', [
      {
        id: uuidv4(),
        firstName: process.env.ADMIN_FIRST_NAME || 'Admin',
        lastName: process.env.ADMIN_LAST_NAME || 'NFS',
        phone: process.env.ADMIN_PHONE || null,
        email,
        city: null,
        role: 'ADMIN',
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ]);

    console.log(`[seeder] Admin user created: ${email}`);
  },

  async down(queryInterface) {
    const email = process.env.ADMIN_EMAIL;
    if (!email) return;

    await queryInterface.bulkDelete('users', { email }, {});
    console.log(`[seeder] Admin user removed: ${email}`);
  },
};


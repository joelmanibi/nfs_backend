require('dotenv').config();

module.exports = {
  development: {
    username: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'NFS',
    host: process.env.DB_HOST || '10.112.30.143',
    port: process.env.DB_PORT || 3306,
    dialect: 'mysql',
    logging: false,
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000,
    },
    timezone: '+00:00',
    dialectOptions: {
      // mysql2 v3 fix: cast TINYINT(1) → boolean (affects DataTypes.BOOLEAN fields)
      typeCast: function (field, next) {
        if (field.type === 'TINY' && field.length === 1) {
          return field.string() === '1';
        }
        return next();
      },
    },
  },
  test: {
    username: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME_TEST || 'NFS_test',
    host: process.env.DB_HOST || '10.112.30.143',
    port: process.env.DB_PORT || 3306,
    dialect: 'mysql',
    logging: false,
    timezone: '+00:00',
  },
  production: {
    username: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    dialect: 'postgres',
    logging: false,
    pool: {
      max: 10,
      min: 2,
      acquire: 30000,
      idle: 10000,
    },
  //  dialectOptions: {
    //  ssl: {
    //    require: true,
    //    rejectUnauthorized: false,
    //  },
  //  },
  },
};


var express = require('express');
const cors = require("cors");
// const client = require('./config/redis.config');

var app = express();
var corsOptions = {
    origin: "*"
  };
app.use(cors(corsOptions));
const bodyParser = require('body-parser');

const db = require("./src/models");
db.sequelize.sync();

app.use(bodyParser.json());

app.use(bodyParser.urlencoded({extended:true}));

app.use('/static', express.static('assets'));

require('./src/routes')(app);

const PORT = process.env.PORT || 8000;
app.listen(PORT,'0.0.0.0', function () {
    console.log(`App listening on port ${PORT}`);
    });
module.exports = app;
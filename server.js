'use strict';
require("rootpath")();
require("dotenv").config({ path: './.env' })
const https = require("https");
const http = require('http');
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const cookieParser = require('cookie-parser');
const mongoose = require("mongoose");
const helmet = require('helmet');
var session = require('express-session')
var log4js = require("log4js");
var logger = log4js.getLogger();
logger.level = "debug";

var init = require('./app/config/initial');

const app = express();

// process .env 
const PORT = process.env.PORT || 8080;
const HOSTNAME = process.env.HOST_API;
const MONGO_URI = process.env.MONGO_URL;

const optionsMoongose = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    autoIndex: true, // Don't build indexes
    maxPoolSize: 10, // Maintain up to 10 socket connections
    serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
    socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
};
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    logger.info(" MongoDB : Connexion  etablie en success ....        ");
    init.initialyRoles();
    init.initialyUser();
})
    .catch((err) => {
        logger.error(` MongoDB Connexion Error : ${err}`);
        process.exit();
    });

var corsOptions = {
    origin: `http://${HOSTNAME}:${PORT}`,
    optionSuccessStatus: 200
};
app.use(cors(corsOptions));
//add security app
app.use(cookieParser());
app.use(helmet.contentSecurityPolicy());
app.use(helmet.dnsPrefetchControl({ allow: true }));
app.use(helmet.expectCt());
app.use(helmet.frameguard());
app.use(helmet.hidePoweredBy());
app.use(helmet.hsts({
    maxAge: 123456,
    includeSubDomains: false,
    preload: true
}));
app.use(helmet.ieNoOpen());
app.use(helmet.noSniff());
app.use(helmet.permittedCrossDomainPolicies());
app.use(helmet.referrerPolicy());
app.use(helmet.xssFilter());

// parse requests of content-type = application/json
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('trust proxy', 1) // trust first proxy
app.use(session({
    secret: require('./app/config/auth.config').secret,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: true,
        maxAge: 60000
    }
}))



/**
 * routes apps
 */
require("./app/routes/auth.routes")(app);


http.createServer(corsOptions, app).listen(PORT, () => {
    logger.info(` Server running at http://${HOSTNAME}:${PORT} ...`);
});

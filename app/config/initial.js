const db = require("../models/index");
var bcrypt = require("bcryptjs");
var log4js = require("log4js");
var logger = log4js.getLogger();
logger.level = "debug";
const Role = db.role;
const User = db.user;

const {
    USERNAME_ADMIN,
    PASSWORD_ADMIN,
    EMAIL_ADMIN
} = process.env;

module.exports = {
    initialyRoles,
    initialyUser
};

function initialyRoles() {
    Role.estimatedDocumentCount((err, count) => {
        if (!err && count === 0) {
            new Role({
                name: "user",
            }).save((err) => {
                if (err) {
                    logger.error(err);
                }
                logger.info("Added 'user' to roles collection");
            });

            new Role({
                name: "manager",
            }).save((err) => {
                if (err) {
                    logger.error(err);
                }
                logger.info("Added 'manager' to roles collection");
            });

            new Role({
                name: "ene",
            }).save((err) => {
                if (err) {
                    logger.error(err);
                }
                logger.info("Added 'ene' to roles collections");
            });

            new Role({
                name: "admin",
            }).save((err) => {
                if (err) {
                    logger.error(err);
                }
                logger.info("Added 'admin' to roles collection");
            });
        }
    });
}

async function initialyUser() {
    User.estimatedDocumentCount((err, count) => {
        if (count === 0 && !err) {
            const user = new User({
                username: USERNAME_ADMIN,
                password: bcrypt.hashSync(PASSWORD_ADMIN, 8),
                email: EMAIL_ADMIN,
            });
            user.save((err, user) => {
                if (err) {
                    logger.error(err);
                }
                Role.find(
                    {
                        name: { $in: ['admin'] },
                    },
                    (err, roles) => {
                        if (err) {
                            logger.error(err);
                        }
                        user.roles = roles.map((role) => role._id);
                        user.save((err) => {
                            if (err) {
                                logger.error(err);
                            }

                            logger.info("Added 'admin' to user collection");

                        });
                    }
                );
            });
        }
    });
}

const jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");
const {TokenExpiredError} = jwt;
const config = require("../config/auth.config.js");
const db = require("../models");
const User = db.user;
const Role = db.role;

const catchError = (err, res) =>{
    if(err instanceof TokenExpiredError){
        return res.status(401).json({ message: `Non autorisé: le jeton d\'accès a expiré !` });
    }
}
verifyToken = (req, res, next) => {
    let token = req.headers["Bearer"];

    if (!token) {
        return res.status(403).json({ message: `Accès impossible: Aucun token fourni ` });
    }
    jwt.verify(token, config.secret, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: err });
        }
        req.userId = decoded.id;
        next();
    });
};
verifyAuth = (req,res, next )=>{
    if(req.headers["Bearer"]){
        let token = req.headers["Bearer"];

        if (!token) {
            return res.status(403).json(`Accès impossible: Aucun token fourni `);
        }
        jwt.verify(token, config.secret, (err, decoded) => {
            if (err) {
                return res.status(401).json(err);
            }
            req.userId = decoded.id;
            next();
        });
    }else if(req.query.username && req.query.password ){
        if(req.query.grant_type && req.query.grant_type === 'ccbih'){
            User.findOne({
                username: req.query.username
            }).populate("roles", "-__v")
                .exec(function (err, user) {
                    if (!user) {
                        return res.status(404).json(`Le nom d\'utilisateur ou le mot de passe est incorrect`);
                    } else {
                        if (!bcrypt.compareSync(req.query.password, user.password)) {
                            return res.status(404).json(`Mot de passe est incorrect `);
                        }else{
                            req.userId = user._id;
                            next();
                        }
                    }
                });
        }else{
            return res.status(404).json( `Le droit d\'autorisation est incorrect !`);
        }
       
    }else{
        return res.status(404).json( `Les informations de connexion est incorrect !`);
    }
}

isAdmin = (req, res, next) => {
    User.findById(req.userId).exec((err, user) => {
        if (err) {
            return res.status(500).json({ message: err });
        }

        Role.find(
            {
                _id: { $in: user.roles }
            },
            (err, roles) => {
                if (err) {
                    return res.status(500).json({ message: err });
                }

                for (let i = 0; i < roles.length; i++) {
                    if (roles[i].name === "admin") {
                        return next();
                    }
                }

                return res.status(403).json({ message: `ERREUR: désolé, vous n'avez pas le droit admin` });

            }
        );
    });
};

isMoe = (req, res, next) => {
    User.findById(req.userId).exec((err, user) => {
        if (err) {
            return res.status(500).json({ message: err });
        }

        Role.find(
            {
                _id: { $in: user.roles }
            },
            (err, roles) => {
                if (err) {
                    return res.status(500).json({ message: err });
                }

                for (let i = 0; i < roles.length; i++) {
                    if (roles[i].name === "moe" || roles[i].name === "user") {
                        return next();
                    }
                }

                return res.status(403).json({ message: `ERREUR: désolé, vous n'avez pas le droit moe ou user` });
            }
        );
    });
};

const authJwt = {
    verifyToken,
    isAdmin,
    isMoe,
    verifyAuth
};
module.exports = authJwt;
const db = require("../models");
const ROLES = db.ROLES;
const User = db.user;

/**
 * function verfi
 */
checkDuplicateUsername = (req, res, next) => {
  // Username
  User.findOne({
    username: req.body.username
  }).exec((err, user) => {
    if (err) {
      return res.status(500).json({ message: err });
    }

    if (user) {
      return res.status(404).json({ message: `ERREUR : Un compte existe déjà pour cet utilisateur « ${req.body.username} » ` });
    }
    next();
  });
};
checkBodyExist = (req,res,next) =>{
    if(!req.body){
        return res.status(401).json({ message: 'ERREUR : le body n\'est pas bien défini, veuillez vérifiez le body' });
    }
    next();
}
checkUsernameExist = (req,res,next) =>{
    if(req.body.username){
        if(!User.findOne({username: req.body.username})){
            return res.status(404).json({
                message: `ERROR : désolé, le username « ${req.body.username} » n'existe pas )`
            });
        }
    }
    next();
}
checkRolesExisted = (req, res, next) => {
  if (req.body.roles) {
    for (let i = 0; i < req.body.roles.length; i++) {
      if (!ROLES.includes(req.body.roles[i])) {
        return res.status(404).json({
          message: `ERREUR : désolé, le rôle « ${req.body.roles[i]} » n'existe pas )`
        });
        
      }
    }
  }

  next();
};

const verifySignUp = {
  checkDuplicateUsername,
  checkRolesExisted,
  checkUsernameExist,
  checkBodyExist
};

module.exports = verifySignUp;
const { verifySignUp } = require('../middlewares');
const controller = require('../controllers/auth.controller');
const BaseUrl = require('../config/constantes');


module.exports = function(app) {
  app.use(function(req, res, next) {
    res.header(
      'Access-Control-Allow-Headers',
      'x-access-token, Origin, Content-Type, Accept'
    );
    next();
  });
  //method post register 
  app.post(
    BaseUrl.endpoint+BaseUrl.version+BaseUrl.AUTH_BASE+BaseUrl.AUTH_SIGNUP,
    [
      verifySignUp.checkDuplicateUsername,
      verifySignUp.checkRolesExisted
    ],
    controller.signup
  );
  // method post authentificate
  app.post(
    BaseUrl.endpoint+BaseUrl.version+BaseUrl.AUTH_BASE+BaseUrl.AUTH_SIGNIN,
    controller.basicAuth,
  );
  
};



module.exports ={
    endpoint: '/api/REST/services',
    version: '/v1',
    // endpoint auth
    AUTH_BASE: '/oauth/token',
    AUTH_SIGNUP : '/signup',
    AUTH_SIGNIN: '/login',

    //endpoint user 
    USER_BASE: '/user',
    USER_FIND_ALL: '/list',
    USER_CREATE: '/add',
    USER_FIND: '/get/:id',
    USER_UPDATE : '/edit/:id',
    USER_DELETE : '/delete/:id',
    FIND_ALL : '/all',

}
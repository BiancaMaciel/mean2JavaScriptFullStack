var passport = require('passport');
var jwt = require('jsonwebtoken');
var passportJWT = require('passport-jwt');
var mongoose = require('mongoose');

var ExtractJwt = passportJWT.ExtractJwt;
var JwtStrategy = passportJWT.Strategy;

var jwtOptions = {
    //armazena o token vindo do cliente
    // jwtFromRequest: ExtractJwt.fromAuthHeader,
    jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('jwt'),
    //palavra secreta para codificar o nosso token
	secretOrKey: 'minhaChaveSecreta'
}

module.exports = {
    //restringir algumas API's
    get auth(){
        var User = mongoose.models.Usuario;

        //estrategia de autenticação
        //jwt_payload é o token com o id do usuário
        var strategy = new JwtStrategy(jwtOptions, function(jwt_payload, next){
            User.findById(jwt_payload._id).exec().then(user =>{
                if(user){
                    next(null, user);
                }else{
                    next(null, false);
                }
            });
        }); 

        passport.use(strategy);

        return {
            initialize: function(){
                return passport.initialize();
            },
            get authenticate(){
                return passport.authenticate('jwt', {session: false});
            }
        }   
    },
    login: function(name, password, callback){
        var User = mongoose.models.Usuario;

        User.findOne({name, password}).exec().then(user => {
            if(user){
                var payload = {_id: user._id};
                var token = jwt.sign(payload, jwtOptions.secretOrKey);

                callback({'message': 'ok', token});
            }
            else{
                callback(false);
            }
        });
    }
}

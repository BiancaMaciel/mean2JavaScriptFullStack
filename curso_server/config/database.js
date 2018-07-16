var mongoose = require('mongoose');

module.exports = function(url){
    mongoose.connect(url);

    mongoose.connection.on('connected', function(){
        console.log('mongoose conectado!');
    })
}
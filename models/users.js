const mongoose = require('mongoose');
mongoose.connect('mongodb://192.168.56.101/challenge', { useNewUrlParser: true } );

const Schema = mongoose.Schema;

const userDataSchema = new Schema({
    username: String,
    password: String,
    email: String,
    role: String
});

let user = module.exports = mongoose.model('users', userDataSchema);

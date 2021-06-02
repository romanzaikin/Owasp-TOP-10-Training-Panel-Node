const express = require('express');
const encode = require('html-entities').encode;
const user = require("../models/users");

const fs = require('fs');

const libxmljs = require("libxmljs");
const mathjs = require('mathjs')


const router = express.Router();
// XSS
router.get('/api/xss/stage/:id', function(req, res, next) {
  switch (req.params.id){
    case "1":
    case "2":
    case "8":
      return res.status(200).send(
        req.query.search
      );

      case "4":
        // add Json content-type to fix the XSS .json instead of .send

        res.setHeader('content-type', 'text/html');
        return res.status(200).send({
            msg: encode(req.query.search),
            country: req.query.country
        });

    case "5":
    case "6":
        return res.status(200).json({
            msg: encode(req.query.search)
        });

    default:
      return res.status(200).json({
        msg: "not found!",
      });
  }
});

// XXE
router.post('/api/xxe/stage/:id', function(req, res, next) {
    switch (req.params.id){
        case "1":
        case "2":
            let xmldata = libxmljs.parseXmlString(req.body.toString('utf8'), {noent:true, noblanks:true})
            return res.status(200).json({msg: `welcome ${xmldata.root().childNodes()[0].text()}`});

        default:
            return res.status(200).json({msg: "not found!"});
    }
});

// RCE + Using component with known vulnerabilities
router.post('/api/safe_calc', function(req, res, next) {

    // solution: https://jwlss.pw/mathjs/
    // https://onlinestringtools.com/convert-decimal-to-string

    res.status(200).json({
        msg: mathjs.eval(req.body.calc)
    });

});
router.post('/api/calc', function(req, res, next) {

    // process.cwd()
    // var fs=require("fs");fs.readdirSync("/app.js").toString('utf8')
    // require('child_process').exec('whoami')

    res.status(200).json({
        msg: eval(req.body.calc)
    });

});

// SSRF
router.get('/api/secret', function(req, res, next) {
    if (req.headers.host.includes("127.0.0.1")){
        res.status(200).send("The password is 'SSRF_Master'");
    }else{
        res.status(200).send("Nothing here");
    }
});

// NO SQLi
router.post('/api/login', function(req, res, next) {

    // "$ne":"a"
    // "$regex" "^A"

    user.findOne({
        $or: [{
            "username": req.body.creds.toLowerCase()
        }, {
            "email": req.body.creds.toLowerCase()
        }],
        "password": req.body.password

    }, (err, docs) => {
        if (err) console.log(err);

        if (docs == null || docs.length == 0) {
            return res.json({ success: false, msg: "username not found or wrong password"});
        }

        return res.json({ msg: `welcome ${docs.username}, role: ${docs.role}` });
    });

});

// NO SQLi Business Logic
router.post('/api/safe_login', function(req, res, next) {

    user.find({
        $or: [{
            "username": req.body.creds.toLowerCase()
        }, {
            "email": req.body.creds.toLowerCase()
        }]
    }, (err, docs) => {
        if (err) console.log(err);

        if (docs == null || docs.length == 0) {
            return res.json({ success: false, msg: "username not found"});
        }

       for(data of docs){

           /* check if password match */
           if (req.body.password == data.password) {
               if (req.body.creds.toLowerCase() == "roman"){
                   return res.json({ msg: `welcome roman, role: admin` });
               }else{
                   return res.json({ msg: `welcome ${data.username}, role: ${data.role}` });
               }
           }
       }

        return res.json({ success: false, msg: "wrong password"});
    });

});
router.post('/api/register', function(req, res, next) {

    user.findOne({
        $or: [{
            "username": req.body.username.toLowerCase()
        }, {
            "email": req.body.email.toLowerCase()
        }]
    }, (err, docs) => {
        if (err) console.log(err);

        if (docs != null) {
            return res.json({ success: false, msg: "user already exists" });
        }

        if (req.body.username.length < 4 || req.body.email.length < 4 ) {
            return res.json({ success: false, msg: "data to short" });
        }

        if (req.body.username.toLowerCase() == "roman"){

            new user({
                username: "roman",
                email: "romans5427173@gmail.com",
                password: "IKnowSQLiInjection",
                role: "admin",
            }).save(function (err, saved_object) {
                return res.json({ success: true ,msg: "registered successfully"});
            });

        }else{
            new user({
                username: req.body.username.toLowerCase(),
                email: req.body.email.toLowerCase(),
                password: req.body.password,
                role: "user",
            }).save(function (err, saved_object) {
                return res.json({ success: true ,msg: "registered successfully"});
            });
        }
    });

});


// General APIs

// report referer url
router.get('/report', function(req, res, next) {
    fs.writeFileSync(`csp.log`, req.headers.referer, 'utf8');
    res.status(200).send("ok");
});
// upload file
router.post('/upload', function(req, res, next) {
    let uploadedFile = req.files.file;

    // Use the mv() method to place the file somewhere on your server
    uploadedFile.mv(`public/uploads/${uploadedFile.name}`, function (err) {
        if (err) return res.status(500).send(err);
        else return res.redirect(`/xss/stage/8?image=${uploadedFile.name}`);
    });

});
// redirect to url
router.get('/redirect', function(req, res, next) {
    return res.redirect(req.query.url);
});
// print user agent
router.get('/api/user', function(req, res, next) {
    res.status(200).send(req.headers["user-agent"]);
});


module.exports = router;

const express = require('express');
const encode = require('html-entities').encode;
const fs = require('fs');
const request = require('request');
const router = express.Router();

/* GET XSS stages. */
router.get('/xss/stage/:id', function(req, res, next) {
  switch (req.params.id) {
    case "1":
    case "2":
    case "3":
    case "4":
    case "5":
    case "6":
    case "7":
    case "8":
      return res.render(`xss/stage${req.params.id}`,
          {
            title: `Stage${req.params.id}`,
            stage: req.params.id,
            search: req.query.search,
            callback: req.query.callback,
            output: "not found",
            image: req.query.image
          });

    case "7_real":
      if( req.headers.referer? req.headers.referer.includes("stage/7") : false){
        return res.render(`xss/stage${req.params.id}`,
            {
              title: `Stage${req.params.id}`,
              stage: req.params.id,
              search: req.query.search,
            });
      }else{
        return res.redirect("/xss/stage/7?callback=/xss/stage/7_real");
      }

    default:
      return res.render("xss/stage1",{title:"Stage1", stage: req.params.id});
  }

});

/* GET RCE stages. */
router.get('/rce/stage/:id', function(req, res, next) {
    switch (req.params.id) {
        case "1":
        case "2":
            return res.render(`rce/stage${req.params.id}`,
                {
                    title: `Stage${req.params.id}`,
                    stage: req.params.id,
                });

        default:
            return res.render("xxe/stage1",{title:"Stage1", stage: req.params.id});
    }

});

/* GET LFI/RFI stages. */
router.get('/file_inclusion/stage/:id', function(req, res, next) {
    let url = "";

    switch (req.params.id) {
        case "1":
            fs.readFile('./views/file_inclusion/'+req.query.file, function (err, data) {

                return res.render(`file_inclusion/stage${req.params.id}`,
                    {
                        title: `Stage${req.params.id}`,
                        stage: req.params.id,
                        output: data
                    });
            });
            break;

        case "2":
            url = req.query.file.includes("http") ? req.query.file : "http://127.0.0.1:3000/logs/data.log"
            console.log(url);
            //2130706433

            request.get(url, async (error, response, body) => {
                return res.render(`file_inclusion/stage${req.params.id}`,
                    {
                        title: `Stage${req.params.id}`,
                        stage: req.params.id,
                        output: body
                    });
            });
            break;

        default:
            return res.render("xxe/stage1",{title:"Stage1", stage: req.params.id});
    }

});

/* GET NOSQLi stages. */
router.get('/nosqli/stage/:id', function(req, res, next) {

    switch (req.params.id) {
        case "1":
        case "2":
        case "3":
            return res.render(`nosqli/stage${req.params.id}`,
                {
                    title: `Stage${req.params.id}`,
                    stage: req.params.id,
                });

        default:
            return res.render("xxe/stage1",{title:"Stage1", stage: req.params.id});
    }

});

/* GET XXE stages. */
router.get('/xxe/stage/:id', function(req, res, next) {
    switch (req.params.id) {
        case "1":
            return res.render(`xxe/stage${req.params.id}`,
                {
                    title: `Stage${req.params.id}`,
                    stage: req.params.id,
                });

        default:
            return res.render("xxe/stage1",{title:"Stage1", stage: req.params.id});
    }

});

/* INDEX. */
router.get(['/','/index'], function(req, res, next) {

    return res.render(`index`,
        {
            title: `OWASP NODE Panel`,
        });
});


module.exports = router;

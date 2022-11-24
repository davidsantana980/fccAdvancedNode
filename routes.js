const passport = require('passport');
const bcrypt = require("bcrypt");

//global middleware
let ensureAuthenticated = (req, res, next) => {
    if(req.isAuthenticated()){
      return next();
    }
    res.redirect("/");
}

module.exports = (app, myDataBase) => {
    app.route('/').get((req, res) => {
        res.render('index', {
            title: 'Connected to Database',
            message: 'Please login',
            showLogin: true,
            showRegistration: true,
            showSocialAuth: true
        });
    });

    app.get("/profile", ensureAuthenticated, (req, res) => {
        res.render("profile", {
            username: req.user.username
        });
    })

    app.post("/profile", (req, res) => {
        res.render("profile", {
          username: req.user.username
        })
    })

    app.route("/register").post((req, res, next) => {
        const hash = bcrypt.hashSync(req.body.password, 12);
        myDataBase.findOne({username: req.body.username}, (err, user) => {
          if (err) next(err); 
          if (user) return (console.log(`User ${user.username} was already created`), res.redirect("/"));
          myDataBase.insertOne({
            username: req.body.username,
            password: hash
          }, (err, returnedDoc) => {
            err ? next(err) : next(null, returnedDoc.ops[0])
          })
        })
      }, 
      passport.authenticate("local", {failureRedirect: "/"}), (req, res, next) => {
            res.redirect("/profile");
      }
    )

    app.post("/login",
        passport.authenticate("local", {
            //MAKES A GET REQUEST
            failureRedirect: "/"
        }),
        //IF AUTHENTICATED
        (req, res) => {
            res.redirect("/profile");
        }
    )

    app.get("/auth/github", passport.authenticate("github"));

    app.get("/auth/github/callback", 
        passport.authenticate("github", {
            failureRedirect: "/"
        }),
        (req, res) => {
            req.session.user_id = req.user.id;
            res.redirect("/chat");
        }
    );

    app.get("/chat", ensureAuthenticated, (req, res) => {
        res.render("chat", {
            user: req.user
        })
    })
  
    app.get("/logout", (req, res) => {
        req.logout();
        res.redirect("/");
    })
    
    app.use((req, res, next) => {
        res.status(404).type("text").send("Not found");
    })
}

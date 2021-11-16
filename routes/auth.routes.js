const router = require("express").Router();
const UserModel = require("../models/User.model");
const bcrypt = require("bcryptjs");

router.get("/signup", (req, res, next) => {
  res.render("auth/signup.hbs");
});

router.post("/signup", (req, res, next) => {
  const { username, password } = req.body;

  if (username == "" || password == "") {
    res.render("auth/signup.hbs", { error: "Please enter all fields" });
    return;
  }

  let passRegEx = new RegExp(
    "(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})"
  );
  if (!passRegEx.test(password)) {
    res.render("auth/signup.hbs", {
      error:
        "Please enter minimum eight characters, at least one uppercase character, one lowercase character, one special character and one number for your password.",
    });
    return;
  }

  let salt = bcrypt.genSaltSync(10);
  let hash = bcrypt.hashSync(password, salt);

  UserModel.create({ username, password: hash })
    .then(() => {
      res.redirect("/");
    })
    .catch((err) => {
      next(err);
    });
});

router.get("/login", (req, res, next) => {
  res.render("auth/login.hbs");
});

router.post("/login", (req, res, next) => {
  const { username, password } = req.body;

  UserModel.find({ username })
    .then((userResponse) => {
      if (userResponse.length) {
        let userObj = userResponse[0];

        let isMatching = bcrypt.compareSync(password, userObj.password);

        if (isMatching) {
          req.session.myProperty = userObj;
          res.redirect("/private");
        } else {
          res.render("auth/login", { error: "Password not matching" });
          return;
        }
      } else {
        res.render("auth/login", { error: "Username does not exist" });
        return;
      }
    })
    .catch((err) => {
      next(err);
    });
});

const checkLogIn = (req, res, next) => {
  if (req.session.myProperty) {
    next();
  } else {
    res.redirect("/signin");
  }
};

router.get("/main", checkLogIn, (req, res, next) => {
    res.render("auth/main");
  });

router.get("/private", checkLogIn, (req, res, next) => {
  let myUserInfo = req.session.myProperty;
  res.render("auth/private", { name: myUserInfo.username });
});

router.get("/logout", (req, res, next) => {
  req.session.destroy();
  res.redirect("/login");
});

module.exports = router;

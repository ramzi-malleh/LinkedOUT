const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const passport = require("passport");

const users = require("./routes/api/users");

const app = express();

// app.use('/', (req,res) => res.send('hello'))

app.use(
  bodyParser.urlencoded({
    extended: false
  })
);
app.use(bodyParser.json());

const db = require("./config/keys").mongoURI;

//connection to Mongo
mongoose
  .connect(db, { useNewUrlParser: true })
  .then(() => console.log("connection success"))
  .catch(err => console.log(err));

app.use(passport.initialize());
require("./config/passport")(passport);
app.use("/api/users", users);

const port = process.env.port || 5000;

app.listen(port, () => console.log(`server up and run on port ${port}`));

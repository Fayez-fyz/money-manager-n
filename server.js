const path = require("path");
const express = require("express");
const dotenv = require("dotenv");
const colors = require("colors");
const morgan = require("morgan");
const connectDB = require("./config/db");
const cors = require("cors");
const mongodb = require("mongodb");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoClient = mongodb.MongoClient;
dotenv.config({ path: "./config/config.env" });

connectDB();

const transactions = require("./routes/transactions");
const PORT = process.env.PORT || 3000;
const app = express();

app.use(express.json());
app.use(
  cors({
    origin: "*",
  })
);
function authenticate(req, res, next) {
  try {
    // Check if the token is present
    // if present -> check if it is valid
    if (req.headers.authorization) {
      jwt.verify(
        req.headers.authorization,
        process.env.JWT_SECRET,
        function (error, decoded) {
          if (error) {
            res.status(500).json({
              message: "Unauthorized",
            });
          } else {
            console.log(decoded);
            req.userid = decoded.id;
            next();
          }
        }
      );
    } else {
      res.status(401).json({
        message: "No Token Present",
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

app.post("/register", async function (req, res) {
  try {
    //connect the database
    let client = await mongoClient.connect(process.env.MONGO_URI);
    //select the db
    let db = client.db("money_manager");
    //hashing passwords
    let salt = bcryptjs.genSaltSync(10);
    let hash = bcryptjs.hashSync(req.body.password, salt);
    req.body.password = hash;
    //select the connection perform the action
    let data = await db.collection("users").insertOne(req.body);
    // close the connection
    await client.close();

    res.json({
      message: "User created",
      id: data._id,
    });
  } catch (error) {
    res.status(500).status({
      message: "Something went wrong",
    });
  }
});

app.post("/login", async function (req, res) {
  try {
    // Connect the Database
    let client = await mongoClient.connect(process.env.MONGO_URI);

    // Select the DB
    let db = client.db("money_manager");

    // Find the user with email_id
    let user = await db
      .collection("users")
      .findOne({ username: req.body.username });

    if (user) {
      // Hash the incoming password
      // Compare that password with user's password
      console.log(req.body);
      console.log(user.password);
      let matchPassword = bcryptjs.compareSync(
        req.body.password,
        user.password
      );
      if (matchPassword) {
        // Generate JWT token
        let token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
        res.json({
          message: true,
          token,
        });
      } else {
        res.status(404).json({
          message: "Username/Password is incorrect",
        });
      }
      // if both are correct then allow them
    } else {
      res.status(404).json({
        message: "Username/Password is incorrect",
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.use("/api/v1/transactions", transactions);

app.listen(
  PORT,
  console.log(`Server running mode on port ${PORT}`.yellow.bold)
);

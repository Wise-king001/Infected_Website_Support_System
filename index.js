// app.js
const express = require("express");
const app = express();
const path = require('path');

// Set the view engine to EJS
app.set("view engine", "ejs");

// Serve static files (like CSS) from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));
console.log(path.join(__dirname, 'public')); // Verify the full path being used
app.use((req, res, next) => {
  console.log(`Request for: ${req.url}`);
  next();
});



// Define routes for pages
app.get("/", (req, res) => {
  res.render("index");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.get("/blog", (req, res) => {
  res.render("blog");
});

// Start the server
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});

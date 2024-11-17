// app.js
const express = require("express");
const app = express();
const path = require("path");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const HavocwebDB = require("havocwebdblite").default;
const session = require("express-session");
const fs = require("fs");
const isAuthenticated = require("./component/authMiddle");

app.use(
  session({
    secret: "nano", // Replace with your own secret key
    resave: false, // Don't save session if unmodified
    saveUninitialized: false, // Don't create session until something is stored
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 24 hours (in milliseconds)
    },
  })
);
app.use(express.urlencoded({ extended: true }));

// Set the view engine to EJS
app.set("view engine", "ejs");

// Serve static files (like CSS) from the "public" directory
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
console.log(path.join(__dirname, "public")); // Verify the full path being used
app.use((req, res, next) => {
  console.log(
    `Request for: ${req.url} : ${req.method} : ${req.ip} : ${req.statusMessage}`
  );
  next();
});
app.use((req, res, next) => {
  // Make the user available in all views
  res.locals.user = req.session.user || null;
  next();
});

app.use(express.urlencoded({ extended: true }));

// Define a middleware to generate a unique ID and store it in req.reportId
app.use((req, res, next) => {
  req.reportId = uuidv4(); // Generate a unique ID
  next();
});
function convertLinks(content) {
  const regex = /{%a="(.*?)",t="(.*?)"%}/g;
  return content.replace(regex, (match, url, text) => {
    return `<a href="${url}" target="_blank">${text}</a>`;
  });
}

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, "uploads", req.reportId); // Use req.reportId as folder name
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage: storage });

const malwares = {
  overheating: {
    name: "Crypto Mining Malware",
    symptoms: ["overheating", "battery_drain", "unusual_activity"],
    solution: "Install antivirus software and uninstall suspicious apps.",
  },
  popups: {
    name: "Adware",
    symptoms: ["popups", "homepage_change", "unwanted_apps"],
    solution:
      "Clear browser cache, remove unwanted extensions, and use an ad blocker.",
  },
  slow_performance: {
    name: "Spyware",
    symptoms: ["slow_performance", "unusual_activity", "unknown_files"],
    solution: "Run a full antivirus scan and check background processes.",
  },
  // Add more malware profiles as needed
};
// Define routes for pages
app.get("/", (req, res) => {
  const { success } = req.query;
  const user = req.session.user || null;
  console.log(user, req.session.user);
  res.render("index", { success: success === "true", user });
});

app.get("/login", async (req, res) => {
  const { error, loc } = req.query;
  const isDB = await HavocwebDB.isDatabaseAvailable();
  if (!isDB) {
    await HavocwebDB.createLocalDB();
  }

  const isTB = await HavocwebDB.isTableAvailable("user");
  console.log("isTableAvailable", isTB);
  if (!isTB) {
    await HavocwebDB.query(
      "CREATE TABLE user (username TEXT, email TEXT, password TEXT, role TEXT)"
    );
  }
  const user = req.session.user || null;
  res.render("login", { user, error, loc });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const Users = await HavocwebDB.query(
      `SELECT * FROM user WHERE email = '${email}'`
    );
    console.log(Users);
    const OUser = Users[0];
    console.log("user", OUser);
    if (OUser !== undefined && OUser !== null) {
      if (OUser.password === password) {
        if (OUser.role === "admin") {
          req.session.user = OUser;
          res.redirect("/admin?success=true");
        } else {
          req.session.user = OUser;
          res.redirect("/");
        }
      } else {
        res.redirect("/login?error=password");
      }
    } else {
      res.redirect("/login?error=user");
    }
  } catch (e) {
    console.log(e);
    res.redirect(
      "/error?errorname=ServerError&errormessage=An internal error occurred"
    );
  }
});
app.get("/signup", async (req, res) => {
  const isDB = await HavocwebDB.isDatabaseAvailable();
  if (!isDB) {
    await HavocwebDB.createLocalDB();
  }

  const isTB = await HavocwebDB.isTableAvailable("user");
  console.log("isTableAvailable", isTB);
  if (!isTB) {
    await HavocwebDB.query(
      "CREATE TABLE user (username TEXT, email TEXT, password TEXT, role TEXT)"
    );
  }
  const user = req.session.user || null;
  res.render("signup", { user });
});
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const isUserExists = await HavocwebDB.query(
      `SELECT * FROM user WHERE email = '${email}'`
    );

    if (isUserExists.length > 0) {
      res.redirect("/signup?error=User already exists");
      return;
    }

    await HavocwebDB.query(
      `INSERT INTO user (username, email, password, role) VALUES ('${username}', '${email}', '${password}', 'user')`
    );
    let role = "user";
    // Automatically log in the user after signup
    req.session.user = { username, email, role };
    res.redirect("/");
  } catch (e) {
    console.log(e);
    res.redirect(`/signup?error=${e}`);
  }
});
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/blog", async (req, res) => {
  const blogFolderPath = path.join(__dirname, "data", "blog");

  // Check if the 'blog' folder exists, and if not, return an empty array
  if (!fs.existsSync(blogFolderPath)) {
    return res.render("blog", { posts: [], user: req.session.user || null });
  }

  // Read all files in the 'blog' folder
  const files = fs.readdirSync(blogFolderPath);

  // Read each file and parse the JSON data
  const blogPosts = files
    .filter((file) => file.endsWith(".json")) // Only JSON files
    .map((file) => {
      const filePath = path.join(blogFolderPath, file);
      const fileData = fs.readFileSync(filePath, "utf-8");
      return JSON.parse(fileData);
    });

  console.log(blogPosts);

  // Sort the posts by time (descending)
  const sortedPosts = blogPosts.sort(
    (a, b) => parseInt(b.time) - parseInt(a.time)
  );

  // Process each post (truncate, format)
  const processedPosts = sortedPosts.map((post) => {
    // Truncate title to 50 characters if too long
    const truncatedTitle =
      post.title.length > 50 ? post.title.substring(0, 50) + "..." : post.title;

    // Truncate body to 25 words
    const truncatedBody = post.body.split(" ").slice(0, 25).join(" ") + "...";

    // Convert the time to a readable format
    const postTime = new Date(parseInt(post.time));
    let formattedTime;
    const now = new Date();
    const differenceInMs = now - postTime;
    const differenceInMinutes = Math.floor(differenceInMs / (1000 * 60));

    if (differenceInMinutes < 60) {
      formattedTime = `${differenceInMinutes} minutes ago`;
    } else if (differenceInMinutes < 180) {
      formattedTime = `${Math.floor(differenceInMinutes / 60)} hours ago`;
    } else if (differenceInMinutes < 1440) {
      formattedTime = "today";
    } else if (differenceInMinutes < 2880) {
      formattedTime = "yesterday";
    } else if (differenceInMinutes < 7200) {
      formattedTime = postTime.toLocaleDateString("en-US", { weekday: "long" });
    } else {
      formattedTime = postTime.toLocaleDateString("en-GB");
    }

    return {
      ...post,
      title: truncatedTitle,
      body: truncatedBody,
      time: formattedTime,
    };
  });

  // Render the blog page with the processed posts
  const user = req.session.user || null;
  res.render("blog", { posts: processedPosts, user });
});

app.get("/blog/:postID", async (req, res) => {
  const { postID } = req.params;

  // Define the path to the blog folder
  const blogFolderPath = path.join(__dirname, "data", "blog");

  // Construct the file path for the specific post
  const postFilePath = path.join(blogFolderPath, `${postID}.json`);

  // Check if the post file exists
  if (!fs.existsSync(postFilePath)) {
    return res.status(404).send("Post not found.");
  }

  // Read and parse the post data from the JSON file
  const fileData = fs.readFileSync(postFilePath, "utf-8");
  const fullPost = JSON.parse(fileData);

  // Format the time as before
  const postTime = new Date(parseInt(fullPost.time));
  let formattedTime;
  const now = new Date();
  const differenceInMs = now - postTime;
  const differenceInMinutes = Math.floor(differenceInMs / (1000 * 60));

  if (differenceInMinutes < 60) {
    formattedTime = `${differenceInMinutes} minutes ago`;
  } else if (differenceInMinutes < 180) {
    formattedTime = `${Math.floor(differenceInMinutes / 60)} hours ago`;
  } else if (differenceInMinutes < 1440) {
    formattedTime = "today";
  } else if (differenceInMinutes < 2880) {
    formattedTime = "yesterday";
  } else if (differenceInMinutes < 7200) {
    formattedTime = postTime.toLocaleDateString("en-US", { weekday: "long" });
  } else {
    formattedTime = postTime.toLocaleDateString("en-GB");
  }

  // Replace custom link syntax with actual HTML anchor tags in the post body
  const processedBody = fullPost.body.replace(
    /{%a="(.*?)",t="(.*?)"%}/g,
    (match, url, text) => {
      return `<a href="${url}" target="_blank" class="blogLink">${text}</a>`;
    }
  );

  // Render the full post page
  const user = req.session.user || null;
  res.render("fullPost", {
    post: { ...fullPost, body: processedBody },
    time: formattedTime,
    user,
  });
});

app.get("/admin/addmalware", isAuthenticated("admin"), async (req, res) => {
  const { success } = req.query;
  const isDB = await HavocwebDB.isDatabaseAvailable();
  if (!isDB) {
    await HavocwebDB.createLocalDB();
  }

  const isTB = await HavocwebDB.isTableAvailable("props");
  console.log("isTableAvailable", isTB);
  if (!isTB) {
    await HavocwebDB.query("CREATE TABLE props (type TEXT, list TEXT)");
  }
  const isTB2 = await HavocwebDB.isTableAvailable("malware");
  console.log("isTableAvailable", isTB2);
  if (!isTB2) {
    await HavocwebDB.query(
      "CREATE TABLE malware (name TEXT, symptom TEXT, behave TEXT, explain TEXT, solution TEXT)"
    );
  }
  res.render("addmalware", { success: success === "true" });
});

app.post("/admin/addmalware", isAuthenticated("admin"), async (req, res) => {
  const { name, symptoms, behave, content, solution } = req.body;

  console.log("Form data received:", req.body);

  try {
    // Paths for files
    const symptomsFile = path.join(__dirname, "data/symptoms", "symptoms.json");
    const behaviorsFile = path.join(
      __dirname,
      "data/behaviors",
      "behaviors.json"
    );
    const malwareFile = path.join(__dirname, "data/malware.json");

    // Ensure directories and files exist
    if (!fs.existsSync(path.dirname(symptomsFile))) {
      fs.mkdirSync(path.dirname(symptomsFile), { recursive: true });
    }
    if (!fs.existsSync(path.dirname(behaviorsFile))) {
      fs.mkdirSync(path.dirname(behaviorsFile), { recursive: true });
    }
    if (!fs.existsSync(malwareFile)) {
      fs.writeFileSync(malwareFile, JSON.stringify([]));
    }

    // Read existing data
    let existingSymptoms = fs.existsSync(symptomsFile)
      ? JSON.parse(fs.readFileSync(symptomsFile, "utf8"))
      : [];
    let existingBehaviors = fs.existsSync(behaviorsFile)
      ? JSON.parse(fs.readFileSync(behaviorsFile, "utf8"))
      : [];
    let malwareData = JSON.parse(fs.readFileSync(malwareFile, "utf8"));

    // Normalize and append new data
    const userSymptoms = symptoms
      .split(",")
      .map((item) => item.trim().toLowerCase());
    const userBehaviors = behave
      .split(",")
      .map((item) => item.trim().toLowerCase());

    userSymptoms.forEach((symptom) => {
      if (!existingSymptoms.includes(symptom)) {
        existingSymptoms.push(symptom);
      }
    });

    userBehaviors.forEach((behavior) => {
      if (!existingBehaviors.includes(behavior)) {
        existingBehaviors.push(behavior);
      }
    });

    // Write updated arrays back to files
    fs.writeFileSync(symptomsFile, JSON.stringify(existingSymptoms, null, 2));
    fs.writeFileSync(behaviorsFile, JSON.stringify(existingBehaviors, null, 2));

    // Append malware data
    malwareData.push({
      name,
      symptoms: userSymptoms,
      behave: userBehaviors,
      content,
      solution,
    });
    fs.writeFileSync(malwareFile, JSON.stringify(malwareData, null, 2));

    res.redirect("/admin/addmalware?success=true");
  } catch (e) {
    console.error("Error saving data:", e);
    res.redirect("/admin/addmalware?success=false");
  }
});

app.get("/report", async (req, res) => {
  try {
    const isDB = await HavocwebDB.isDatabaseAvailable();
    if (!isDB) {
      await HavocwebDB.createLocalDB();
    }

    const isTB = await HavocwebDB.isTableAvailable("report");
    console.log("isTableAvailable", isTB);
    if (!isTB) {
      await HavocwebDB.query(
        "CREATE TABLE report (Uniqueid TEXT, symptoms TEXT, device TEXT, operatingSystem TEXT, apps TEXT, networkType TEXT, antiVirus TEXT, images TEXT, Behavior TEXT)"
      );
    }
    // Paths for files
    const symptomsFile = path.join(__dirname, "data/symptoms", "symptoms.json");
    const behaviorsFile = path.join(
      __dirname,
      "data/behaviors",
      "behaviors.json"
    );

    // Ensure files exist
    const symptoms = fs.existsSync(symptomsFile)
      ? JSON.parse(fs.readFileSync(symptomsFile, "utf8"))
      : [];
    const behaviors = fs.existsSync(behaviorsFile)
      ? JSON.parse(fs.readFileSync(behaviorsFile, "utf8"))
      : [];

    console.log("Symptoms:", symptoms);
    console.log("Behaviors:", behaviors);
    const user = req.session.user || null;
    // Render the report page with symptoms and behaviors
    res.render("report", { symptoms, behaviors, user });
  } catch (error) {
    console.error("Error loading data:", error);
    res.status(500).send("Error loading report data.");
  }
});

app.post("/report", upload.array("screenshot", 3), async (req, res) => {
  const {
    symptoms,
    device_type,
    os_version,
    recent_apps,
    network_type,
    last_scan_date,
    behavior,
  } = req.body;

  try {
    const reportId = req.reportId || `report_${Date.now()}`; // Fallback if req.reportId is missing
    const files = req.files || [];
    const imagePaths = files.map((file) => file.path);

    const reportData = {
      reportId,
      symptoms: symptoms || [],
      device_type: device_type || "Unknown",
      os_version: os_version || "Unknown",
      recent_apps: recent_apps || [],
      network_type: network_type || "Unknown",
      last_scan_date: last_scan_date || "Unknown",
      behavior: behavior || "No behavior provided",
      images: imagePaths,
    };

    // Define the directory and file paths
    const directoryPath = path.join(__dirname, "data/report");
    const filePath = path.join(directoryPath, `${reportId}.json`);

    // Ensure the directory exists
    if (!fs.existsSync(directoryPath)) {
      fs.mkdirSync(directoryPath, { recursive: true });
      console.log(`Directory created: ${directoryPath}`);
    }

    // Write report data to a JSON file
    fs.writeFileSync(filePath, JSON.stringify(reportData, null, 2));

    console.log("Report Saved:", reportData);

    // Redirect to the results page with the report ID
    res.redirect(`/report-results?y=true&id=${reportId}`);
  } catch (e) {
    console.error("Error saving data to the report file", e);
    res.status(500).render("report", { success: false, error: "An error occurred while saving the report." });
  }
});

app.get("/report-results", async (req, res) => {
  const { id } = req.query;

  try {
    if (!id) {
      return res.status(400).send("Report ID is required");
    }

    // Define the file path for the JSON report
    const filePath = path.join(__dirname, `data/report/${id}.json`);

    // Check if the report file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).send("Report not found");
    }

    // Read and parse the JSON file
    const reportData = JSON.parse(fs.readFileSync(filePath, "utf8"));

    // Combine symptoms and behavior
    const userIndicators = [
      ...(reportData.symptoms || []),
      ...(reportData.behavior || []),
    ];

    // Path to the malware JSON file
    const malwareFilePath = path.join(__dirname, "data/malware.json");
    const malwares = JSON.parse(fs.readFileSync(malwareFilePath, "utf8"));

    // Match user symptoms and behavior with malware data
    const matchedMalware = malwares
      .map((malware) => {
        const symptomMatchCount = malware.symptoms.filter((symptom) =>
          userIndicators.includes(symptom.toLowerCase())
        ).length;

        return symptomMatchCount > 1
          ? {
              malware: malware.name,
              content: malware.content,
              solution: malware.solution,
              match_strength: symptomMatchCount,
            }
          : null;
      })
      .filter(Boolean);

    // Sort matched malware by match strength
    matchedMalware.sort((a, b) => b.match_strength - a.match_strength);

    // Prepare data for rendering
    const mainMalware =
      matchedMalware.length > 0
        ? {
            name: matchedMalware[0].malware,
            explanation: `${matchedMalware[0].content} This malware matches ${matchedMalware[0].match_strength} of your symptoms/behaviors.`,
            solution: matchedMalware[0].solution,
          }
        : null;

    const secondaryMalware =
      matchedMalware.length > 1
        ? {
            name: matchedMalware[1].malware,
            solution: matchedMalware[1].solution,
          }
        : null;
    const user = req.session.user || null;
    // Render the feedback page with the diagnosis
    res.render("feedback", {
      Malware: mainMalware?.name || "None",
      MainMalwareExplained: mainMalware?.explanation || "No malware detected.",
      MainMalwareSolution: mainMalware?.solution || "No solution required.",
      Malware2: secondaryMalware?.name || "None",
      Malware2Solution: secondaryMalware?.solution || "No solution required.",
      user,
    });
  } catch (e) {
    console.error("Error fetching report results:", e);
    res
      .status(500)
      .send("An error occurred while retrieving the report results.");
  }
});
app.get("/admin/login", async (req, res) => {
  const { error, loc } = req.query;
  const isDB = await HavocwebDB.isDatabaseAvailable();
  if (!isDB) {
    await HavocwebDB.createLocalDB();
  }

  const isTB = await HavocwebDB.isTableAvailable("user");
  console.log("isTableAvailable", isTB);
  if (!isTB) {
    await HavocwebDB.query(
      "CREATE TABLE user (username TEXT, email TEXT, password TEXT, role TEXT)"
    );
  }
  res.render("admin", { error, loc });
});
app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const Users = await HavocwebDB.query(
      `SELECT * FROM user WHERE email = '${email}'`
    );
    console.log(Users);
    const OUser = Users[0];
    if (OUser !== undefined && OUser !== null) {
      if (OUser.password === password) {
        if (OUser.role === "admin") {
          req.session.user = OUser;
          res.redirect("/admin?success=true");
        } else {
          res.redirect(
            "/error?errorname=UnAuthorized Access&errormessage=You are not allowed to Login as an Administrator, Use the User Login instead"
          );
        }
      } else {
        res.redirect("/admin/login?error=password");
      }
    } else {
      res.redirect("/admin/login?error=user");
    }
  } catch (e) {
    console.log(e);
    res.redirect(
      "/error?errorname=ServerError&errormessage=An internal error occurred"
    );
  }
});
app.get("/admin", isAuthenticated("admin"), async (req, res) => {
  const isDB = await HavocwebDB.isDatabaseAvailable();
  if (!isDB) {
    await HavocwebDB.createLocalDB();
  }

  const isTB = await HavocwebDB.isTableAvailable("blog");
  console.log("isTableAvailable", isTB);
  if (!isTB) {
    await HavocwebDB.query(
      "CREATE TABLE blog (postID TEXT, title TEXT, body TEXT, imgurl TEXT, time TEXT)"
    );
  }
  const { success, bs } = req.query;
  res.render("adminhome", {
    success: success === "true",
    blogged: bs === "true",
  });
});
app.get("/admin/create", async (req, res) => {
  const isDB = await HavocwebDB.isDatabaseAvailable();
  if (!isDB) {
    await HavocwebDB.createLocalDB();
  }

  const isTB = await HavocwebDB.isTableAvailable("user");
  console.log("isTableAvailable", isTB);
  if (!isTB) {
    await HavocwebDB.query(
      "CREATE TABLE user (username TEXT, email TEXT, password TEXT, role TEXT)"
    );
  }

  res.render("createadmin");
});
app.post("/admin/create", async (req, res) => {
  const { username, email, password, code } = req.body;
  let og_code = "000000";
  try {
    if (code === og_code) {
      await HavocwebDB.query(
        `INSERT INTO user (username, email, password, role) VALUES (${username}, ${email}, ${password}, 'admin')`
      );
      res.redirect("/admin/login?loc=signup");
    } else {
      res.redirect(
        "/error?errorname=UnAuthorized Access&errormessage=You are not allowed to Sign-Up as an Administrator, Use the User Sign-Up instead"
      );
    }
  } catch (e) {
    console.log(e);
    res.redirect(
      "/error?errorname=ServerError&errormessage=An internal error occurred"
    );
  }
});
app.post(
  "/blog",
  isAuthenticated("admin"),
  upload.array("image", 3),
  async (req, res) => {
    const { title, content } = req.body;
    const time = new Date().getTime();
    const reportId = req.reportId; // Assuming `reportId` is available in `req`

    const postID = reportId;
    const body = content;

    // Construct the URLs for each uploaded file
    const imageUrls = req.files.map(
      (file) => `/uploads/${reportId}/${path.basename(file.path)}`
    );

    // Prepare the blog data to be written to a file
    const blogData = {
      postID,
      title,
      body,
      imgurl: imageUrls,
      time,
    };

    // Define the path for the new blog post file
    const blogFolderPath = path.join(__dirname, "data", "blog");

    // Create the blog folder if it doesn't exist
    if (!fs.existsSync(blogFolderPath)) {
      fs.mkdirSync(blogFolderPath, { recursive: true });
    }

    // Define the file path for this blog post
    const blogFilePath = path.join(blogFolderPath, `${postID}.json`);

    // Write the blog data to the file
    try {
      fs.writeFileSync(blogFilePath, JSON.stringify(blogData, null, 2));
      console.log("Blog post saved:", blogFilePath);

      // Redirect to the admin page with success flag
      res.redirect("/admin?bs=true");
    } catch (error) {
      console.error("Error saving blog post:", error);
      res.status(500).send("Failed to save the blog post.");
    }
  }
);

app.get("/error", (req, res) => {
  const query = req.query;
  console.log(query);
  const user = req.session.user || null;
  res.render("Error", {
    errorname: query.errorname,
    errormessage: query.errormessage,
    user,
  });
});
// Start the server
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});

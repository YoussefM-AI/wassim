const express = require("express");
const path = require("path");
const fs = require("fs-extra");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const app = express();
const USERS_FILE = path.join(__dirname, "users.json");
const ADMIN_SECRET = "rahti2026"; // Secret code for admin registration

// Middleware
app.use(express.static(__dirname));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: 'rahti-secret-key-123',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  }
}));

// Ensure users.json exists
async function ensureUsersFile() {
  if (!(await fs.pathExists(USERS_FILE))) {
    await fs.writeJson(USERS_FILE, []);
  }
}
ensureUsersFile();

// Home route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "wassim.html"));
});

// Get current user info (including history)
app.get("/api/user", async (req, res) => {
  if (req.session.user) {
    const users = await fs.readJson(USERS_FILE);
    const user = users.find(u => u.email === req.session.user.email);
    if (user) {
      const { password, ...userWithoutPassword } = user;
      res.json({ success: true, user: userWithoutPassword });
    } else {
      res.status(401).json({ success: false, message: "User not found" });
    }
  } else {
    res.status(401).json({ success: false, message: "Not logged in" });
  }
});

// Admin API: Get all users
app.get("/api/admin/users", async (req, res) => {
  if (req.session.user && req.session.user.role === 'admin') {
    const users = await fs.readJson(USERS_FILE);
    // Filter out passwords and return all users
    const safeUsers = users.map(({ password, ...rest }) => rest);
    res.json({ success: true, users: safeUsers });
  } else {
    res.status(403).json({ success: false, message: "Forbidden" });
  }
});

// Save test result
app.post("/api/save-test", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }

  try {
    const { score, category } = req.body;
    const users = await fs.readJson(USERS_FILE);
    const userIndex = users.findIndex(u => u.email === req.session.user.email);

    if (userIndex === -1) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (!users[userIndex].tests) {
      users[userIndex].tests = [];
    }

    users[userIndex].tests.push({
      score,
      category,
      date: new Date()
    });
    
    await fs.writeJson(USERS_FILE, users);
    res.json({ success: true, message: "Test saved successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Error saving test result" });
  }
});

// Registration route
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, age, sexe, hopital, service, experience, adminCode } = req.body;
    
    const users = await fs.readJson(USERS_FILE);
    
    if (users.find(u => u.email === email)) {
      return res.status(400).json({ success: false, message: "This user already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const role = (adminCode === ADMIN_SECRET) ? "admin" : "user";
    
    const newUser = {
      name,
      email,
      password: hashedPassword,
      age,
      sexe,
      hopital,
      service,
      experience,
      role,
      tests: [],
      createdAt: new Date()
    };
    
    users.push(newUser);
    await fs.writeJson(USERS_FILE, users);
    
    req.session.user = { name: newUser.name, email: newUser.email, role: newUser.role };
    res.json({ success: true, redirect: role === "admin" ? "/admin-dashboard.html" : "/dashboard.html" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Error during registration." });
  }
});

// Login route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const users = await fs.readJson(USERS_FILE);
    const user = users.find(u => u.email === email);
    
    if (!user) {
      return res.status(400).json({ success: false, message: "Incorrect email or password." });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: "Incorrect email or password." });
    }
    
    req.session.user = { name: user.name, email: user.email, role: user.role };
    res.json({ success: true, redirect: user.role === "admin" ? "/admin-dashboard.html" : "/dashboard.html" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Error during login." });
  }
});

// Logout route
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/wassim.html");
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});

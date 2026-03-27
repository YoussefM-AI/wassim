require('dotenv').config();
const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const mongoose = require("mongoose");

const app = express();
const ADMIN_SECRET = "rahti2026"; // Secret code for admin registration

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://Rahti:rahti2026@cluster0.vz1u9w3.mongodb.net/?appName=Cluster0";
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch(err => console.error('Could not connect to MongoDB:', err));

// Test Schema (sub-document)
const testSchema = new mongoose.Schema({
  score: Number,
  category: String,
  answers: [Number],
  exercise: {
    pensee: String,
    emotion: String,
    newPensee: String
  },
  date: { type: Date, default: Date.now }
});

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  age: Number,
  sexe: String,
  hopital: String,
  service: String,
  experience: Number,
  tests: [testSchema],
  checklists: [{
    date: { type: Date, default: Date.now },
    items: [String]
  }],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Middleware
app.use(express.static(__dirname));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'rahti-secret-key-123',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  }
}));

// Home route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'home.html'));
});

// Get current user info (including history)
app.get("/api/user", async (req, res) => {
  if (req.session.user) {
    try {
      const user = await User.findOne({ email: req.session.user.email }).select('-password');
      if (user) {
        res.json({ success: true, user });
      } else {
        res.status(401).json({ success: false, message: "User not found" });
      }
    } catch (error) {
      res.status(500).json({ success: false, message: "Server error" });
    }
  } else {
    res.status(401).json({ success: false, message: "Not logged in" });
  }
});

// Admin API: Get all users
app.get("/api/admin/users", async (req, res) => {
  if (req.session.user && req.session.user.role === 'admin') {
    try {
      const users = await User.find().select('-password');
      res.json({ success: true, users });
    } catch (error) {
      res.status(500).json({ success: false, message: "Server error" });
    }
  } else {
    res.status(403).json({ success: false, message: "Forbidden" });
  }
});

// Admin API: Delete a user
app.delete("/api/admin/user/:id", async (req, res) => {
  if (req.session.user && req.session.user.role === 'admin') {
    try {
      const { id } = req.params;
      
      // Prevent self-deletion
      const userToDelete = await User.findById(id);
      if (userToDelete && userToDelete.email === req.session.user.email) {
        return res.status(400).json({ success: false, message: "You cannot delete your own admin account." });
      }

      const result = await User.findByIdAndDelete(id);
      if (result) {
        res.json({ success: true, message: "User deleted successfully" });
      } else {
        res.status(404).json({ success: false, message: "User not found" });
      }
    } catch (error) {
      res.status(500).json({ success: false, message: "Server error during deletion" });
    }
  } else {
    res.status(403).json({ success: false, message: "Forbidden" });
  }
});

// Admin API: Delete a specific test from user history
app.delete("/api/admin/user/:userId/test/:testId", async (req, res) => {
  if (req.session.user && req.session.user.role === 'admin') {
    try {
      const { userId, testId } = req.params;
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ success: false, message: "Utilisateur non trouvé" });
      }

      // Use Mongoose's pull method to remove the sub-document by ID
      user.tests.pull({ _id: testId });
      await user.save();
      
      res.json({ success: true, message: "Test supprimé avec succès" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: "Erreur lors de la suppression du test" });
    }
  } else {
    res.status(403).json({ success: false, message: "Interdit" });
  }
});

// Admin API: Toggle user role (user <-> admin)
app.post("/api/admin/user/toggle-role/:id", async (req, res) => {
  if (req.session.user && req.session.user.role === 'admin') {
    try {
      const { id } = req.params;
      const user = await User.findById(id);
      if (!user) {
        return res.status(404).json({ success: false, message: "User not found" });
      }

      // Prevent self-demotion
      if (user.email === req.session.user.email) {
        return res.status(400).json({ success: false, message: "You cannot change your own role." });
      }

      // Toggle role
      user.role = (user.role === 'admin') ? 'user' : 'admin';
      await user.save();
      
      res.json({ success: true, message: `Role changed to ${user.role}`, newRole: user.role });
    } catch (error) {
      res.status(500).json({ success: false, message: "Server error during role toggle" });
    }
  } else {
    res.status(403).json({ success: false, message: "Forbidden" });
  }
});

// Admin API: Reset user password to default
app.post("/api/admin/user/reset-password/:id", async (req, res) => {
  if (req.session.user && req.session.user.role === 'admin') {
    try {
      const { id } = req.params;
      const user = await User.findById(id);
      if (!user) {
        return res.status(404).json({ success: false, message: "User not found" });
      }

      const defaultPassword = "Rahti" + new Date().getFullYear(); // e.g., Rahti2026
      user.password = await bcrypt.hash(defaultPassword, 10);
      await user.save();
      
      res.json({ success: true, message: `Mot de passe réinitialisé à: ${defaultPassword}` });
    } catch (error) {
      res.status(500).json({ success: false, message: "Server error during password reset" });
    }
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
    const { score, category, answers } = req.body;
    const user = await User.findOne({ email: req.session.user.email });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    user.tests.push({
      score,
      category,
      answers,
      date: new Date()
    });
    
    await user.save();
    res.json({ success: true, message: "Test saved successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Error saving test result" });
  }
});

// User API: Save exercise answers for the most recent test
app.post("/api/user/save-exercise", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }

  try {
    const { pensee, emotion, newPensee } = req.body;
    const user = await User.findOne({ email: req.session.user.email });

    if (!user || user.tests.length === 0) {
      return res.status(404).json({ success: false, message: "No tests found to attach exercise to" });
    }

    // Attach exercise to the most recent test
    const latestTest = user.tests[user.tests.length - 1];
    latestTest.exercise = { pensee, emotion, newPensee };
    
    await user.save();
    res.json({ success: true, message: "Exercice enregistré avec succès" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Erreur lors de l'enregistrement de l'exercice" });
  }
});

// User API: Save daily well-being checklist
app.post("/api/user/save-checklist", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }

  try {
    const { items } = req.body;
    const user = await User.findOne({ email: req.session.user.email });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    user.checklists.push({
      date: new Date(),
      items
    });
    
    await user.save();
    res.json({ success: true, message: "Checklist enregistrée avec succès !" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Erreur lors de l'enregistrement de la checklist" });
  }
});

// User API: Change password (while logged in)
app.post("/api/user/change-password", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }

  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findOne({ email: req.session.user.email });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: "Mot de passe actuel incorrect." });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    
    res.json({ success: true, message: "Mot de passe mis à jour avec succès !" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error during password change" });
  }
});

// User API: Update full profile info
app.post("/api/user/update-profile", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }

  try {
    const { name, age, sexe, hopital, service, experience } = req.body;
    const user = await User.findOne({ email: req.session.user.email });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Update fields
    if (name) user.name = name;
    if (age) user.age = age;
    if (sexe) user.sexe = sexe;
    if (hopital) user.hopital = hopital;
    if (service) user.service = service;
    if (experience) user.experience = experience;

    await user.save();
    
    // Update session info if name changed
    req.session.user.name = user.name;
    
    res.json({ success: true, message: "Profil mis à jour avec succès !" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Erreur lors de la mise à jour du profil" });
  }
});

// Registration route
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, age, sexe, hopital, service, experience, adminCode } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "This user already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const role = (adminCode === ADMIN_SECRET) ? "admin" : "user";
    
    const newUser = new User({
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
    });
    
    await newUser.save();
    
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
    
    const user = await User.findOne({ email });
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

// Forgot Password Recovery (Public)
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email, name, newPassword } = req.body;
    
    // Find user by email AND name for extra verification
    const user = await User.findOne({ email, name });
    
    if (!user) {
      return res.status(400).json({ success: false, message: "Les informations fournies ne correspondent à aucun compte." });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    
    res.json({ success: true, message: "Mot de passe réinitialisé avec succès ! Vous pouvez maintenant vous connecter." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Error during password recovery." });
  }
});

// Logout route
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/home.html");
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});

require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("./db");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

/* ================= REGISTER ================= */
app.post("/register", async (req, res) => {
  try {
    const { name, mobile, password } = req.body;

    if (!name || !mobile || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    // Check if mobile already exists
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE mobile=$1",
      [mobile]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "Mobile already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert user
    await pool.query(
      "INSERT INTO users (name, mobile, password) VALUES ($1,$2,$3)",
      [name, mobile, hashedPassword]
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ================= LOGIN ================= */
app.post("/login", async (req, res) => {
  try {
    const { mobile, password } = req.body;

    const user = await pool.query(
      "SELECT * FROM users WHERE mobile=$1",
      [mobile]
    );

    if (user.rows.length === 0) {
      return res.status(400).json({ message: "Invalid mobile or password" });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.rows[0].password
    );

    if (!validPassword) {
      return res.status(400).json({ message: "Invalid mobile or password" });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user.rows[0].id, mobile: user.rows[0].mobile },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: "Login successful",
      token: `Bearer ${token}`,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ================= PROTECTED ROUTE ================= */
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(403).json({ message: "Token required" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    req.user = decoded;
    next();
  });
};

app.get("/profile", verifyToken, async (req, res) => {
  const user = await pool.query(
    "SELECT id, name, mobile FROM users WHERE id=$1",
    [req.user.id]
  );
  res.json(user.rows[0]);
});

app.get("/hello", async (req, res) => {
//   const user = await pool.query(
//     "SELECT 1+1 FROM users",
//   );
  res.json({"message: ":"hello"});
});

/* ================= ADD MEAL ================= */
app.post("/add-meal", verifyToken, async (req, res) => {
  try {
    const { meal_flag, meal_name } = req.body;

    if (meal_flag === undefined || !meal_name) {
      return res.status(400).json({ message: "Meal flag and name required" });
    }

    // Validate flag
    if (![0, 1, 2].includes(meal_flag)) {
      return res.status(400).json({ message: "Invalid meal flag" });
    }

    await pool.query(
      "INSERT INTO meals (user_id, meal_flag, meal_name) VALUES ($1,$2,$3)",
      [req.user.id, meal_flag, meal_name]
    );

    res.status(201).json({ message: "Meal added successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/* ================= GET USER MEALS ================= */
app.get("/meals", verifyToken, async (req, res) => {
  try {
    const meals = await pool.query(
      "SELECT id, meal_flag, meal_name FROM meals WHERE user_id=$1 ORDER BY meal_flag",
      [req.user.id]
    );

    res.json(meals.rows);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/meals-customers", async (req, res) => {
  try {
    const { name, user_id } = req.query;
    if (!name && !user_id) {
      return res.json({ message: "Please provide user_id or name" });
    }

    // const meals = await pool.query(
    //   `SELECT m.id, m.meal_flag, m.meal_name, u.name
    //    FROM meals m
    //    JOIN users u ON m.user_id = u.id
    //    WHERE ($1::int IS NULL OR u.id = $1)
    //    AND ($2::text IS NULL OR u.name = $2)
    //    ORDER BY m.meal_flag`,
    //   [user_id || null, name || null]
    // );
    const meals = await pool.query(
      "SELECT id, meal_flag, meal_name FROM meals WHERE user_id=$1 ORDER BY meal_flag",
      [user_id]
    );

    res.json(meals.rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/user-status", verifyToken, async (req, res) => {
  try {
    const { status_flag } = req.query;

    if (!status_flag) {
      const user = await pool.query(
        "SELECT status_flag FROM users WHERE id=$1",
        [req.user.id]
      );

      if (user.rows.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      return res.json({
        userId: req.user.id,
        status_flag: user.rows[0].status_flag
      });
    }

    // 🔹 If provided → validate
    if ([0, 1].includes(status_flag)) {
      return res.status(400).json({ message: "Invalid status flag (use 0 or 1)" });
    }

    // 🔹 Update status
    await pool.query(
      "UPDATE users SET status_flag=$1 WHERE id=$2",
      [status_flag, req.user.id]
    );

    return res.json({
      status_flag
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});


app.listen(process.env.PORT, () =>
  console.log(`Server running on port ${process.env.PORT}`)
);
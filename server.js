require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("./db");
const cors = require("cors");
const multer = require("multer");
const { put, list } = require("@vercel/blob");

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
      process.env.JWT_SECRET
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
    const { meals } = req.body;

    if (!Array.isArray(meals) || meals.length === 0) {
      return res.status(400).json({ message: "Meals array required" });
    }

    // 🔹 1. Separate restore & insert
    const restoreIds = [];
    const insertMeals = [];

    for (const meal of meals) {
      if (meal.meal_id) {
        const parsedId = parseInt(meal.meal_id, 10);
        if (!Number.isInteger(parsedId)) {
          return res.status(400).json({ message: "Invalid meal_id" });
        }
        restoreIds.push(parsedId);
      } else {
        insertMeals.push(meal);
      }
    }

    await pool.query("BEGIN");

    let restoredCount = 0;
    let insertedCount = 0;

    // 🔥 2. Bulk Restore
    if (restoreIds.length > 0) {
      const restoreResult = await pool.query(
        `UPDATE meals
         SET is_deleted = 0
         WHERE id = ANY($1)
         AND user_id = $2
         RETURNING id`,
        [restoreIds, req.user.id]
      );

      restoredCount = restoreResult.rowCount;
    }

    // 🔥 3. Bulk Insert
    if (insertMeals.length > 0) {

      const values = [];
      const placeholders = [];

      insertMeals.forEach((meal, index) => {
        const { meal_flag, meal_name, meal_price } = meal;

        if (meal_flag === undefined || !meal_name) {
          throw new Error("Meal flag and name required");
        }

        if (![0, 1, 2].includes(meal_flag)) {
          throw new Error("Invalid meal flag");
        }

        const parsedPrice =
          meal_price !== undefined ? Number(meal_price) : null;

        if (meal_price !== undefined && (isNaN(parsedPrice) || parsedPrice < 0)) {
          throw new Error("Invalid meal_price");
        }

        const baseIndex = index * 4;

        placeholders.push(
          `($${baseIndex + 1}, $${baseIndex + 2}, $${baseIndex + 3}, $${baseIndex + 4}, 0)`
        );

        values.push(
          req.user.id,
          meal_flag,
          meal_name,
          parsedPrice
        );
      });

      const insertQuery = `
        INSERT INTO meals
        (user_id, meal_flag, meal_name, meal_price, is_deleted)
        VALUES ${placeholders.join(",")}
      `;

      await pool.query(insertQuery, values);

      insertedCount = insertMeals.length;
    }

    await pool.query("COMMIT");

    res.json({
      message: "Operation completed successfully",
      restored: restoredCount,
      inserted: insertedCount
    });

  } catch (err) {
    await pool.query("ROLLBACK");
    console.error(err);
    res.status(400).json({ error: err.message });
  }
});

// app.post("/add-meal", verifyToken, async (req, res) => {
//   try {
//     const { meal_flag, meal_name } = req.body;

//     if (meal_flag === undefined || !meal_name) {
//       return res.status(400).json({ message: "Meal flag and name required" });
//     }

//     // Validate flag
//     if (![0, 1, 2].includes(meal_flag)) {
//       return res.status(400).json({ message: "Invalid meal flag" });
//     }

//     await pool.query(
//       "INSERT INTO meals (user_id, meal_flag, meal_name) VALUES ($1,$2,$3)",
//       [req.user.id, meal_flag, meal_name]
//     );

//     res.status(201).json({ message: "Meal added successfully" });

//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: err.message });
//   }
// });

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

app.get("/current-meals", verifyToken, async (req, res) => {
  try {
    const meals = await pool.query(
      "SELECT id, meal_flag, meal_name, meal_price FROM meals WHERE user_id=$1 AND is_deleted=0 ORDER BY meal_flag",
      [req.user.id]
    );

    res.json(meals.rows);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/meals/:id", verifyToken, async (req, res) => {
  try {
    const mealId = parseInt(req.params.id, 10);
    const softDelete = parseInt(req.query.soft_delete, 10);

    if (!Number.isInteger(mealId)) {
      return res.status(400).json({ message: "Invalid meal id" });
    }

    let result;

    // 🔹 If soft_delete=1 → Soft Delete
    if (softDelete === 1) {
      result = await pool.query(
        `UPDATE meals 
         SET is_deleted = 1 
         WHERE id = $1 AND user_id = $2 AND is_deleted = 0
         RETURNING *`,
        [mealId, req.user.id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({ message: "Meal not found or already deleted" });
      }

      return res.json({ message: "Meal soft deleted successfully" });
    }

    // 🔹 Otherwise → Permanent Delete
    result = await pool.query(
      `DELETE FROM meals 
       WHERE id = $1 AND user_id = $2 
       RETURNING *`,
      [mealId, req.user.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "Meal not found" });
    }

    res.json({ message: "Meal permanently deleted" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// app.delete("/meals/:id", verifyToken, async (req, res) => {
//   try {
//     const mealId = parseInt(req.params.id, 10);

//     if (!Number.isInteger(mealId)) {
//       return res.status(400).json({ message: "Invalid meal id" });
//     }

//     const result = await pool.query(
//       "DELETE FROM meals WHERE id = $1 AND user_id = $2 RETURNING *",
//       [mealId, req.user.id]
//     );

//     if (result.rowCount === 0) {
//       return res.status(404).json({ message: "Meal not found" });
//     }

//     res.json({ message: "Meal deleted successfully" });

//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

app.get("/meals-customers", async (req, res) => {
  try {
    const { name, user_id } = req.query;
    if (!name && !user_id) {
      return res.json({ message: "Please provide user_id or name" });
    }

    // 🔹 Capture visitor IP
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    // 🔹 Insert visit record WITH user_id
    await pool.query(
      `INSERT INTO api_visits (endpoint, ip_address, user_id)
       VALUES ($1, $2, $3)`,
      ["/meals-customers", ip, user_id || null]
    );

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
      "SELECT id, meal_flag, meal_name, meal_price FROM meals WHERE user_id=$1 AND is_deleted=0 ORDER BY meal_flag",
      [user_id]
    );

     // 🔹 Get user name
    const userResult = await pool.query(
      `SELECT name FROM users WHERE id = $1`,
      [user_id]
    );

    const user_name = userResult.rows[0].name;

    const prefix = `users/${user_id}/`;

    const { blobs } = await list({
      prefix,
      token: process.env.BLOB_READ_WRITE_TOKEN
    });

    const imageUrls = blobs.map(blob => blob.url);

    res.json({ user_name, meals: meals.rows, image_urls: imageUrls });

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
        "SELECT name as user_name, status_flag FROM users WHERE id=$1",
        [req.user.id]
      );

      if (user.rows.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      return res.json({
        userId: req.user.id,
        status_flag: user.rows[0].status_flag,
        user_name: user.rows[0].user_name,
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


//===========================dashboard=========================
// app.get("/dashboard/my-visits", verifyToken, async (req, res) => {
//   try {
//     const userId = req.user.id;
//     const result = await pool.query(
//       `SELECT 
//           COUNT(*) AS total_visits,
//           COUNT(DISTINCT ip_address) AS unique_visitors,
//           COUNT(*) FILTER (WHERE DATE(visited_at)=CURRENT_DATE) AS today_visits,
//           COUNT(DISTINCT ip_address) FILTER (WHERE DATE(visited_at)=CURRENT_DATE) AS today_unique_visitors
//       FROM api_visits
//       WHERE endpoint = '/meals-customers'
//       AND user_id = $1`,
//       [userId]
//     );

//     res.json({
//       user_id: userId,
//       total_visits: parseInt(result.rows[0].total_visits, 10),
//       unique_visitors: parseInt(result.rows[0].unique_visitors, 10),
//       today_visits: parseInt(result.rows[0].today_visits, 10),
//       today_unique_visitors: parseInt(result.rows[0].today_unique_visitors, 10),
//     });

//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: err.message });
//   }
// });

app.get("/dashboard/my-visits", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // 🔹 1. Overall + Current Month Stats
    const overall = await pool.query(
      `SELECT 
          COUNT(*) AS total_visits,
          COUNT(DISTINCT ip_address) AS unique_visitors,

          COUNT(*) FILTER (
              WHERE DATE(visited_at)=CURRENT_DATE
          ) AS today_visits,

          COUNT(DISTINCT ip_address) FILTER (
              WHERE DATE(visited_at)=CURRENT_DATE
          ) AS today_unique_visitors,

          COUNT(*) FILTER (
              WHERE EXTRACT(MONTH FROM visited_at)=EXTRACT(MONTH FROM CURRENT_DATE)
              AND EXTRACT(YEAR FROM visited_at)=EXTRACT(YEAR FROM CURRENT_DATE)
          ) AS current_month_visits,

          COUNT(DISTINCT ip_address) FILTER (
              WHERE EXTRACT(MONTH FROM visited_at)=EXTRACT(MONTH FROM CURRENT_DATE)
              AND EXTRACT(YEAR FROM visited_at)=EXTRACT(YEAR FROM CURRENT_DATE)
          ) AS current_month_unique_visitors

       FROM api_visits
       WHERE endpoint = '/meals-customers'
       AND user_id = $1`,
      [userId]
    );

    // 🔹 2. Monthly Stats (ONLY till current month)
    const monthly = await pool.query(
      `SELECT 
          EXTRACT(MONTH FROM visited_at) AS month,
          COUNT(*) AS monthly_visits,
          COUNT(DISTINCT ip_address) AS monthly_unique_visitors
       FROM api_visits
       WHERE endpoint = '/meals-customers'
       AND user_id = $1
       AND EXTRACT(YEAR FROM visited_at) = EXTRACT(YEAR FROM CURRENT_DATE)
       GROUP BY month
       ORDER BY month`,
      [userId]
    );

    const currentMonth = new Date().getMonth() + 1;

    // 🔹 Create months only till current month
    const months = Array.from({ length: currentMonth }, (_, i) => ({
      month: i + 1,
      monthly_visits: 0,
      monthly_unique_visitors: 0
    }));

    monthly.rows.forEach(row => {
      const index = row.month - 1;
      if (index < currentMonth) {
        months[index] = {
          month: parseInt(row.month, 10),
          monthly_visits: parseInt(row.monthly_visits, 10),
          monthly_unique_visitors: parseInt(row.monthly_unique_visitors, 10)
        };
      }
    });

    res.json({
      user_id: userId,

      total_visits: parseInt(overall.rows[0].total_visits, 10),
      unique_visitors: parseInt(overall.rows[0].unique_visitors, 10),

      today_visits: parseInt(overall.rows[0].today_visits, 10),
      today_unique_visitors: parseInt(overall.rows[0].today_unique_visitors, 10),

      current_month_visits: parseInt(overall.rows[0].current_month_visits, 10),
      current_month_unique_visitors: parseInt(overall.rows[0].current_month_unique_visitors, 10),

      monthly_stats: months
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

app.post("/upload-meals-images", verifyToken, upload.array("images", 10), async (req, res) => {
    try {
      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ message: "Images required" });
      }

      // Validate all files first
      for (const file of req.files) {
        if (!file.mimetype.startsWith("image/")) {
          return res.status(400).json({ message: "Only images allowed" });
        }
      }

      const uploadPromises = req.files.map(file => {
        const timestamp = Date.now();
        const safeName = file.originalname.replace(/\s+/g, "_");
        const fileName = `${timestamp}_${safeName}`;

        return put(
          `users/${req.user.id}/${fileName}`,
          file.buffer,
          {
            access: "public",
            token: process.env.BLOB_READ_WRITE_TOKEN,
            contentType: file.mimetype
          }
        );
      });

      // Upload in parallel (fast)
      const blobs = await Promise.all(uploadPromises);

      const imageUrls = blobs.map(blob => blob.url);

      res.json({
        message: "Images uploaded successfully",
        total_uploaded: imageUrls.length,
        images: imageUrls
      });

    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  }
);

app.get("/user-meals-images", verifyToken, async (req, res) => {
  try {
    const prefix = `users/${req.user.id}/`;

    const { blobs } = await list({
      prefix,
      token: process.env.BLOB_READ_WRITE_TOKEN
    });

    const imageUrls = blobs.map(blob => blob.url);

    res.json({
      user_id: req.user.id,
      total_images: imageUrls.length,
      images: imageUrls
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.listen(process.env.PORT, () =>
  console.log(`Server running on port ${process.env.PORT}`)
);
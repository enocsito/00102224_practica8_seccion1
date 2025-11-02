import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cors from "cors";
import pool from "./db.js";

const app = express();
const PORT = 5000;
const JWT_SECRET = "your_jwt_secret";

app.use(bodyParser.json());
app.use(cors());

//hashed password function

const generateHashedPassword = async (password = "123456!") => {
  const saltRounds = 10;

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  console.log(`Contraseña original: ${password}`);
  console.log(`Hashed password: ${hashedPassword}`);
  return hashedPassword;
}


const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// Routes

// Home endpoint
app.get("/", (req, res) => {
  res.status(200).json({ message: "Welcome to the API", status: "running" });
});


app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = userResult.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({ token });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.post("/api/video", verifyToken, async (req, res) => {
  try {
    const { title, url } = req.body;

    if (!title || !url) {
      return res.status(400).json({ message: "Title and URL are required" });
    }

    const newVideo = {
      id: Date.now(),
      title: title,
      url: url,
      ownerId: req.user.id,
    };

    console.log("Nuevo video creado:", newVideo);

    res.status(201).json({ message: "Video created successfully", video: newVideo });

  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.get("/users", verifyToken, (req, res) => {
  pool.query('SELECT * FROM users ORDER BY id ASC', (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ message: "Error fetching users" });
    }
    res.status(200).json(results.rows);
  });
});

app.get("/users/:id", verifyToken, (req, res) => {
  const id = parseInt(req.params.id);

  pool.query('SELECT * FROM users WHERE id = $1', [id], (error, results) => {
    if (error) {
      throw error;
    }
    res.status(200).json(results.rows);
  });
});

app.post("/users", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email, and password are required" });
    }

    const existingUserResult = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (existingUserResult.rows.length > 0) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, hashedPassword]
    );

    console.log("Usuario creado:", result.rows[0]);
    res.status(201).json({
      message: "User created successfully",
      user: result.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.put("/users/:id", verifyToken, (request, response) => {
  const id = parseInt(request.params.id)
  const { name, email } = request.body

  pool.query(
    'UPDATE users SET name = $1, email = $2 WHERE id = $3',
    [name, email, id],
    (error, results) => {
      if (error) {
        throw error
      }
      response.status(200).send(`User modified with ID: ${id}`)
    }
  )
})

app.delete("/users/:id", verifyToken, (request, response) => {
  const id = parseInt(request.params.id)

  pool.query('DELETE FROM users WHERE id = $1', [id], (error, results) => {
    if (error) {
      throw error
    }
    response.status(200).send(`User deleted with ID: ${id}`)
  })
});

app.get("/generate-hash", async (req, res) => {
  try {
    await generateHashedPassword();
    res.status(200).json({ message: "Check console for hashed password" });
  } catch (error) {
    res.status(500).json({ message: "Error generating hash" });
  }
});



app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));



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

const users = []; 

//hashed password function

const generateHashedPassword = async () => {
  const password = "123456!";
  const saltRounds = 10;

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  console.log(`Contraseña original: ${password}`);
  console.log(`Hashed password: ${hashedPassword}`);
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

app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const existingUser = users.find((u) => u.email === email);
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10); 
    const newUser = {
      id: Date.now().toString(),
      email: email,
      password: hashedPassword,
    };
    users.push(newUser);
    console.log(users); 
    res.status(201).json({ message: "User registered successfully" });

  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);
  if (!user) return res.status(404).json({ message: "User not found" });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });
  res.status(200).json({ token });
});

app.get("/protected", verifyToken, (req, res) => {
  res.status(200).json({ message: "Protected data accessed", user: req.user });
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

app.get("/users", (req, res) => {
  pool.query('SELECT * FROM users ORDER BY id ASC', (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ message: "Error fetching users" });
    }
    res.status(200).json(results.rows);
  });
});

app.get("/users/:id", (req, res) => {
  const id = parseInt(req.params.id);

  pool.query('SELECT * FROM users WHERE id = $1', [id], (error, results) => {
    if (error) {
      throw error;
    }
    res.status(200).json(results.rows);
  });
});

app.post("/users", (req, res) => {
  const { name, email } = req.body;

  pool.query('INSERT INTO users (name, email) VALUES ($1, $2) RETURNING *', [name, email], (error, results) => {
    if (error) {
      throw error;
    }
    res.status(201).send(`User added with ID: ${results.rows[0].id}`);
  });
});

app.post("/users/:id", (request, response) => {
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

app.delete("/users/:id",(request, response) => {
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



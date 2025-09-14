require('dotenv').config();
const cors = require("cors");
const http = require("http");
const express = require("express");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const { MongoClient, ObjectId } = require("mongodb");
const WebSocket = require("ws");
const jwt = require("jsonwebtoken");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({server});
const sockets = new Map();
const log = console.log;

const clientPromise = MongoClient.connect(process.env.DB_URI, {
  useUnifiedTopology: true,
  maxPoolSize: 10,
});

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: ['http://127.0.0.1:5173', 'http://127.0.0.1:5174'],
  credentials: true
}));


app.use(async (req, res, next) => {
  try {
    const client = await clientPromise;
    req.db = client.db("social-network");
    next();
  } catch (err) { next(err) }
});

app.post("/login", bodyParser.urlencoded({ extended: false }), async (req, res) => {
  const { email, password } = req.body;
  const user = await req.db.collection("users").findOne({ email });

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const token = jwt.sign(
    {id: user._id.toString(), username: user.username },
    process.env.JWT_SECRET,
    {expiresIn: "7d"}
  )

  res.json({ token, username: user.username, id: user._id });
})

app.post("/signup", bodyParser.urlencoded({ extended: false }), async (req, res) => {
  const { username, email, dateBirth, password } = req.body;
  
  const existingEmail = await req.db.collection("users").findOne({ email });
  if (existingEmail) return res.status(409).json({ error: "Email already exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  await req.db.collection("users").insertOne({ username, email, dateBirth, passwordHash });
  res.status(201).send("User created");
})

function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  log(authHeader)
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.get("/user", authMiddleware, async (req, res) => {
  const { userId } = req.query;
  const user = await req.db.collection("users").findOne(
    { _id: new ObjectId(userId) },
    { projection: { _id: 1, username: 1, dateBirth: 1 } }
  );
  res.json(user);
})

app.get('/users', async (req, res) => {
  const users = await req.db.collection("users")
    .find({}, { projection: { _id: 1, username: 1, dateBirth: 1 } }).toArray();

  res.json(users);
});

app.get('/messages', async (req, res) => {
  const { myUserId, recipientId } = req.query;
  const messages = await req.db.collection("messages").find().toArray();

  const chat = messages.filter(
    m =>
      (m.myUserId === myUserId && m.recipientId === recipientId) ||
      (m.myUserId === recipientId && m.recipientId === myUserId)
  );
  res.json(chat);
});

clientPromise.then(client => {
  const messages = client.db("social-network").collection("messages");

  wss.on('connection', (ws) => {
    let myUserId = '';
    let recipientId = '';

    ws.on('message', async (data) => {
      try {
        const msg = JSON.parse(data);
        const recipient = sockets.get(msg.recipientId);
        recipientId = msg.recipientId;
        
        if (msg.type === 'login') {
          myUserId = msg.myUserId;
          username = msg.username;
          
          if (recipient?.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'isOnline', isOnline: true }));
            recipient.send(JSON.stringify({ type: 'isOnline', isOnline: true }));
          } else {
            ws.send(JSON.stringify({ type: 'isOnline', isOnline: false }))
          }
          
          sockets.set(myUserId, ws);
          // log(`Пользователь ${username} вошел в чат`);
          return;
        }
        
        if (msg.type === 'typing' || msg.type === 'stop-typing') {
          if (recipient?.readyState === WebSocket.OPEN) {
            recipient.send(JSON.stringify(msg));
          }
        }
        
        if (msg.type === 'message') {
          const { myUserId, recipientId, username, recipientName, message, timestamp } = msg;
          await messages.insertOne({ myUserId, recipientId, username, recipientName, message, timestamp });
          
          if (recipient?.readyState === WebSocket.OPEN) {
            recipient.send(JSON.stringify(msg));
          }
        }
        if (msg.type === 'delete-message') {
          await messages.deleteOne({ timestamp: msg.msgId });
          [recipient, ws].forEach(client => {
            if (client?.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify(msg));
            }
          });
        }
        
      } catch (e) { console.error(e.message) };
    });
  
    ws.on('close', async () => {
      if (!myUserId && !recipientId) return;
      const recipient = sockets.get(recipientId);
      if (recipient?.readyState === WebSocket.OPEN) {
        recipient.send(JSON.stringify({ type: 'isOnline', isOnline: false }));
      }

      sockets.delete(myUserId);
      // log(`Пользователь ${username} вышел из чата`);
    });
  });
})

app.use((err, req, res) => res.status(500).send(err.message));

const port = 3000;
server.listen(port, () => log(`http://127.1.0.1:${port}`));


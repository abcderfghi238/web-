// server.js (demo, not production ready)
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// in-file sqlite
const db = new sqlite3.Database('./eja.db');
db.serialize(()=>{
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT
  )`);
});

// Register
app.post('/api/register', async (req, res)=>{
  const { username, email, password } = req.body;
  if(!username||!email||!password) return res.status(400).json({error:'Lengkapi data.'});
  const hash = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (username,email,password) VALUES (?,?,?)', [username,email,hash], function(err){
    if(err) return res.status(400).json({error: err.message});
    res.json({ok:true, id: this.lastID});
  });
});

// Login
app.post('/api/login', (req,res)=>{
  const { ident, password } = req.body;
  if(!ident||!password) return res.status(400).json({error:'Lengkapi data.'});
  db.get('SELECT * FROM users WHERE username = ? OR email = ?', [ident, ident], async (err, row)=>{
    if(err) return res.status(500).json({error:err.message});
    if(!row) return res.status(401).json({error:'Akun tidak ditemukan.'});
    const match = await bcrypt.compare(password, row.password);
    if(!match) return res.status(401).json({error:'Password salah.'});
    // Return minimal user info (in real app sign JWT)
    res.json({ok:true, id: row.id, username: row.username, email: row.email});
  });
});

app.listen(3000, ()=> console.log('Server running on http://localhost:3000'));

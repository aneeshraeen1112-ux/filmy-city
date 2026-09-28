const express=require("express");
const session=require("express-session");
const multer=require("multer");
const bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const path=require("path");
const fs=require("fs");

const app=express(), PORT=process.env.PORT||3000;
const db=new Database("filmycity.db");
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password TEXT);
CREATE TABLE IF NOT EXISTS movies(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,year TEXT,genre TEXT,rating TEXT,description TEXT,poster TEXT,trailer TEXT);`);
const admin=db.prepare("SELECT * FROM users WHERE username=?").get("admin");
if(!admin) db.prepare("INSERT INTO users(username,password) VALUES(?,?)").run("admin",bcrypt.hashSync(process.env.ADMIN_PASSWORD||"change-me-now",12));

fs.mkdirSync(path.join(__dirname,"uploads"),{recursive:true});
const upload=multer({dest:path.join(__dirname,"uploads/")});
app.use(express.json({limit:"2mb"}));
app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||"replace-this-secret",resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax",secure:false}}));
app.use(express.static(__dirname));

function auth(req,res,next){if(!req.session.admin)return res.status(401).json({error:"Unauthorized"});next()}
app.get("/api/movies",(req,res)=>res.json(db.prepare("SELECT * FROM movies ORDER BY id DESC").all()));
app.post("/api/login",(req,res)=>{const u=db.prepare("SELECT * FROM users WHERE username=?").get(req.body.username);if(u&&bcrypt.compareSync(req.body.password,u.password)){req.session.admin=true;return res.json({ok:true})}res.status(401).json({error:"Invalid login"})});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({admin:!!req.session.admin}));
app.post("/api/movies",auth,(req,res)=>{const {title,year,genre,rating,description,poster,trailer}=req.body;if(!title)return res.status(400).json({error:"Title required"});const r=db.prepare("INSERT INTO movies(title,year,genre,rating,description,poster,trailer) VALUES(?,?,?,?,?,?,?)").run(title,year,genre,rating,description,poster,trailer);res.json({id:r.lastInsertRowid})});
app.put("/api/movies/:id",auth,(req,res)=>{const {title,year,genre,rating,description,poster,trailer}=req.body;db.prepare("UPDATE movies SET title=?,year=?,genre=?,rating=?,description=?,poster=?,trailer=? WHERE id=?").run(title,year,genre,rating,description,poster,trailer,req.params.id);res.json({ok:true})});
app.delete("/api/movies/:id",auth,(req,res)=>{db.prepare("DELETE FROM movies WHERE id=?").run(req.params.id);res.json({ok:true})});
app.post("/api/upload",auth,upload.single("poster"),(req,res)=>{if(!req.file)return res.status(400).json({error:"No file"});res.json({url:"/uploads/"+req.file.filename})});
app.use("/uploads",express.static(path.join(__dirname,"uploads")));
app.listen(PORT,()=>console.log("Filmy City running on port "+PORT));
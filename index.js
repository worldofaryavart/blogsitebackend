const dotenv = require("dotenv");
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const User = require('./models/User');
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const app = express();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path'); 
const fs = require('fs');
const crypto = require('crypto');
const { promisify } = require('util');

dotenv.config();

const uploadMiddleware = multer({dest: 'uploads/'});

const saltRounds = 10;
const secret = crypto.randomBytes(32).toString('hex');

app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads',express.static(__dirname +'/uploads'));

// Use a single promise-based method for renaming files
const renameAsync = promisify(fs.rename);

// const mongo_url = process.env.MONGO_URL;
const mongo_url = "mongodb+srv://myblog1:myblog1234@cluster0.6fty7cj.mongodb.net/mydatabase?retryWrites=true&w=majority"
mongoose
  .connect(mongo_url, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error(err));
// mongoose.connect('mongodb://localhost/myblog', { useNewUrlParser: true, useUnifiedTopology: true });

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const userDoc = await User.create({
      username,
      password: hashedPassword,
    });
    res.json(userDoc);
  } catch (e) {
    console.error(e);
    res.status(400).json(e);
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });
  if (!userDoc) {
    res.status(400).json('User not found');
    return;
  }
  const passOk = await bcrypt.compare(password, userDoc.password);
  if (passOk) {
    const token = jwt.sign({ username, id: userDoc._id }, secret, {});
    res.cookie('token', token, { httpOnly: true }); // Store token in an HttpOnly cookie for better security
    res.json({
      id: userDoc._id,
      username,
    });
  } else {
    res.status(400).json('Wrong credentials');
  }
});

app.get('/profile', (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    res.status(401).json('Unauthorized');
    return;
  }
  jwt.verify(token, secret, {}, (err, info) => {
    if (err) {
      res.status(401).json('Unauthorized');
      return;
    }
    res.json(info);
  });
});

app.post('/logout', (req, res) => {
  res.clearCookie('token'); // Clear the token cookie
  res.json('Logged out');
});

app.post('/post',uploadMiddleware.single('file'),async (req,res) =>{
  const {originalname,path} = req.file;
  const parts = originalname.split('.');
  const ext = parts[parts.length-1];
  const newPath = path+'.'+ext;
  fs.renameSync(path,newPath);

  const {token} =req.cookies;
  jwt.verify(token,secret,{},async (err,info) =>{
    if(err) throw err;
    const {title,summary,content} = req.body;
    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover:newPath,
      author:info.id,
    });
    res.json({postDoc});
  });
})

app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
  let newPath = null;
  if (req.file) {
    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    newPath = path + '.' + ext;
    fs.renameSync(path, newPath);
  }

  const { token } = req.cookies;
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) throw err;
    const { id, title, summary, content } = req.body;
    const postDoc = await Post.findById(id);
    const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
    if (!isAuthor) {
      return res.status(400).json('you are not the author');
    }

    // Use updateOne instead of update
    await Post.updateOne(
      { _id: id },
      {
        $set: {
          title,
          summary,
          content,
          cover: newPath ? newPath : postDoc.cover,
        },
      }
    );

    // Retrieve the updated document
    const updatedPostDoc = await Post.findById(id);

    res.json(updatedPostDoc);
  });
});


app.get('/post', async (req, res) => {
  res.json(
    await Post.find()
    .populate('author',['username'])
    .sort({createdAt:-1})
    .limit(20)
  )
});

app.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  const postDoc = await Post.findById(id).populate('author', 'username');
  if (!postDoc) {
    res.status(404).json('Post not found');
    return;
  }
  res.json(postDoc);
});

app.listen(4000, () => {
  console.log('Server is running on port 4000');
});


// MONGO_URL="mongodb+srv://myblog1:myblog1234@cluster0.6fty7cj.mongodb.net/?retryWrites=true&w=majority"
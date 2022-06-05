/////////////////modules///////////////
const express = require('express');
const path = require('path'); 
const PORT = process.env.PORT || 24680
const app = express();
const MongoDB =  require('mongodb');
const expressip = require('express-ip');
const expressdevice = require('express-device');
const bodyParser = require('body-parser');
const geoip = require('geoip-lite');

const { SHA3 } = require('sha3');
const crypto = require('crypto');

const config = require('./config.json');
MongoClient = new MongoDB.MongoClient(encodeURI(config.mongodb) , { useUnifiedTopology: true } );
var ObjectId = MongoDB.ObjectId; 
const FirstKey = "yBLTAJlcAeZABQiXsrDEv5CVuqO0fZa5";

function GetRandomString(LENGTHTEXT)
{
  let codereturn = ''
  let textcache   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  for (let i = 1; i<= LENGTHTEXT ; i++)
  codereturn  += textcache.charAt(Math.floor(Math.random() *textcache.length))
  return codereturn;
}

function GetRandom(min, max) {
  return Math.floor(Math.random() * (max - min) ) + min;
}

function GetRandomCode() {
  code = ""
  for (let i = 1; i <= 8 ; i++) {
    code += GetRandom(0,9)
  }

  return code;
}


function ToTickCSharp(timestamp) {
  return (timestamp * 10000) + 621355968000000000
}


function HashPassword(password) {
  let hash = new SHA3(512);
  hash.update(password);
  return hash.digest('hex');
}

function GenerateAESKey() {
  return GetRandomString(32);
}

function Encrypt(plaintext, key) {
  const iv = new crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let enc1 = cipher.update(plaintext, 'utf8');
  let enc2 = cipher.final();

  return Buffer.concat([enc1, enc2, iv, cipher.getAuthTag()]).toString("base64");
}

function Decrypt(ciphertext, key) {
  try {
    enc = Buffer.from(ciphertext, "base64");
    const iv = enc.slice(enc.length - 28, enc.length - 16);
    const tag = enc.slice(enc.length - 16);
    enc = enc.slice(0, enc.length - 28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    let str = decipher.update(enc, null, 'utf8');
    str += decipher.final('utf8');
    return str;
  }
  catch (err) {
    console.log("Decrypt Error for key " + key)
  }
  return null;
}

async function main()
{
  process.env.TZ = "Asia/Ho_Chi_Minh";
  console.log(`Started At : ${new Date().toLocaleString('vi-VN')}`)
  await MongoClient.connect();
  console.log("Database connected");


  app
    .set('views', path.join(__dirname, 'public'))
    .set('view engine', 'ejs')
    .engine('html', require('ejs').renderFile)  
    .use(expressip().getIpInfoMiddleware)
    .use(expressdevice.capture())
    .get("/ping", async (req, res) => {
      try {
        res.json({data : Date.now()});
      }
      catch (e) {
        console.log(e)
      }
    })
    .get("/login", async (req, res) => {
      try {
        console.log("WRONGG")
        
      }
      catch (e) {
        console.error(e)
        return res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      }
    })
    .use(bodyParser())
    
    // POST without token
    .post("/firstPOST", async (req, res) => {
      try {
        let body = JSON.parse(Decrypt(req.body.data, FirstKey))
        let key = GenerateAESKey()
        await MongoClient.db("main").collection("userkeys").deleteMany( {  ip : req.ipInfo.ip})
        await MongoClient.db("main").collection("userkeys").insertOne( {  ip : req.ipInfo.ip,  key : key})
        console.log(`Create Key for ${req.ipInfo.ip} : ${key}`)
        return res.status(200).json({ data : Encrypt( JSON.stringify({key : key}),  body.key) })
      }
      catch (e) {
        console.error(e)
        return res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      }
    })
    //Decrypt/Encrypt Init
    .post("/*", async (req, res, next) => {
      try {
        let findKey = await MongoClient.db("main").collection("userkeys").find({ ip : req.ipInfo.ip }).toArray()
        if (findKey.length != 0) {
          let key = findKey[0].key
          console.log(`Found key for ${req.ipInfo.ip} : ${key}`)
          let decrypted = Decrypt(req.body.data, key)
          if (!decrypted)
            return res.status(403).json({})
          req.body =  JSON.parse(decrypted)
          req.body = JSON.parse(req.body)
          req.key = key
          res.locals.json = function (obj) {
            return res.status(200).json({data : Encrypt(JSON.stringify(obj), req.key)})
          }
          next()
        }
        else return res.status(403).json({})
      }
      catch (e) {
        console.error(e)
        return res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      }        
    })
    .post("/login" , async (req, res) => {
      let body = req.body;
      let username = (body.username || "").trim().toLowerCase();
      let password = (body.password || "").trim();

      console.log("Request Login ",body);
      if (!username)
        return res.status(406).json({ error : "Username không hợp lệ"});

      if (!password)
        return res.status(406).json({ error : "Password không hợp lệ"});
    

      let data = await MongoClient.db("main").collection("users").find({username: username}).toArray()
      if (data.length != 0) { 
        console.log(data[0].hashedPassword,  HashPassword(password), data[0].hashedPassword == HashPassword(password))
        if (data[0].hashedPassword == HashPassword(password)) {
          let device = {
            ip : req.ipInfo.ip,
            type : req.device.type,
            location : "UNKNOWN"
          }

          
          let location = geoip.lookup(device.ip);
          if (location)
            device.location = `${location.city}, ${location.region}, ${location.country}`

          console.log("Device Info", device)
          let code = GetRandomCode()

          console.log(`Generate PIN for ${username} : ${code}`)
          await MongoClient.db("main").collection("usercodes").insertOne({ username: username, code : code, ip : device.ip, type : device.type, location : device.location, requestTime : new Date(), isAuth : false})
          res.locals.json({ code : code })
        }
        else 
          return res.status(406).json({ error : "Mật khẩu không đúng"})
      }
      else  return res.status(406).json({ error : "Tên tài khoản không tồn tại"})
    })    
    .post("/gettoken" , async (req, res) => {
      let body = req.body;
      let code = (body.code || "").trim();

      console.log("Request Get Token From Code ", code);
      if (!code)
        return res.status(406).json({ error : "code không hợp lệ"});

      let data = await MongoClient.db("main").collection("usercodes").find({code: code, ip : req.ipInfo.ip, type : req.device.type}).toArray()
      if (data.length != 0 && data[0].isAuth) { 
        let token = GetRandomString(75)
        console.log("Get Token from Code", data)
        await MongoClient.db("main").collection("usercodes").deleteMany({code: code, ip : req.ipInfo.ip, type : req.device.type}).toArray()
        await MongoClient.db("main").collection("usertokens").insertOne( { username : data[0].username, token : token, ip : data[0].ip, canAuth : false})
        console.log(`Create Token For User ${data[0].username} : ${token}`)

        res.locals.json({token : token})
      }
      else  return res.status(406).json({ error : "Mã xác thực không hợp lệ hoặc chưa được cấp quyền"})
    })
    .post("/*", async (req, res, next) => {
      try {
        let findUser = await MongoClient.db("main").collection("usertokens").find({ token : req.body.token }).toArray()
        if (findUser.length != 0) {
          let username = findUser[0].username
          let canAuth = findUser[0].canAuth
          console.log(`Auth Success for user ${username}`)
          
          req.username = username
          req.canAuth = canAuth
          next()
        }
        else return res.status(406).json({ error : "Phiên đăng nhập không hợp lệ"})
      }
      catch (e) {
        console.error(e)
        return res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      }        
    })
    .post("/getinfo" , async (req, res) => {
      if (!req.canAuth)
        return res.status(406).json({ error : "Thiết bị không có quyền xác minh"});

      let body = req.body;
      let code = (body.code || "").trim();

      console.log("Request Get Code Info ", code);
      if (!code)
        return res.status(406).json({ error : "code không hợp lệ"});

      let data = await MongoClient.db("main").collection("usercodes").find({code: code, username : req.username}).toArray()
      if (data.length != 0 && !data[0].isAuth) { 

        data = data[0]
        delete data._id
        data.requestTime = ToTickCSharp(data.requestTime)
        console.log(`Get info Auth Code`, data)  
        res.locals.json(data) 
        
      }
      else  return res.status(406).json({ error : "Mã xác thực bạn nhập không đúng"})
    })
    .post("/confirm" , async (req, res) => {
      if (!req.canAuth)
        return res.status(406).json({ error : "Thiết bị không có quyền xác minh"});

      let body = req.body;
      let code = (body.code || "").trim();

      console.log("Confirm Auth ", code);
      if (!code)
        return res.status(406).json({ error : "code không hợp lệ"});

      let data = await MongoClient.db("main").collection("usercodes").find({code: code, username : req.username}).toArray()
      if (data.length != 0 && !data[0].isAuth) { 
        await MongoClient.db("main").collection("usercodes").updateOne({code: code, username : req.username}, {$set : {isAuth : true}})
        res.locals.json({message : "Đã cấp quyền thành công"}) 
      }
      else  return res.status(406).json({ error : "Mã xác thực bạn nhập không đúng"})
    })
  
  .listen(PORT, () => console.info("WebApp" , `Listening on ${ PORT }`))



}



main();

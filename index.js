/////////////////modules///////////////
const express = require('express');
const path = require('path'); 
const PORT = process.env.PORT || 5000
const app = express();
const MongoDB =  require('mongodb');
const expressip = require('express-ip');
const expressdevice = require('express-device');
const bodyParser = require('body-parser');
const { SHA3 } = require('sha3');
const crypto = require('crypto');
const fetch = require('node-fetch');

const config = require('./config.json');
MongoClient = new MongoDB.MongoClient(encodeURI(config.mongodb) , { useUnifiedTopology: true } );
var ObjectId = MongoDB.ObjectId; 

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
  return ((timestamp + 7*60*60*1000)* 10000) + 621355968000000000
}

async function GetLocationFromIp(ip) {
  try {
    let data = await fetch(`http://ip-api.com/json/${ip}`).then(d => d.json())
    if (data.status == 'success')
      return `${data.city}, ${data.regionName}, ${data.country}`
  }
  catch (e) {
    console.error(e)
  }

  return "UNKNOWN"
}


function HashSHA3512(password) {
  let hash = new SHA3(512);
  hash.update(password);
  return hash.digest('hex');
}

function HashKey(ip, user) {
  let hash = new SHA3(256);
  hash.update(`${HashSHA3512(ip)}|WmEzAt39YeZn9gOZRz3rOu58YjE5PLvVzutol9y|${HashSHA3512(user)}`);
  return hash.digest({format: 'binary'});
}

const RSA = {
  Encrypt(plaintext, publicKey) {
    try {
      let enc =  crypto.publicEncrypt(
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        },
        Buffer.from(plaintext)
      );

      return enc.toString("base64")
    }
    catch (err) {
      console.log("RSA: Encrypt Error for key " + publicKey)
    }
    return null;

  },
  Decrypt(ciphertext, privateKey) {
    try {
      let dec = crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        },
        Buffer.from(ciphertext, "base64"),
      );
      return dec.toString()
    }
    catch (err) {
      console.log("RSA: Decrypt Error for key " + privateKey)
    }
  }
}



const AES = {
  Encrypt(plaintext, key) {
    try {
      const iv = new crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
      let enc1 = cipher.update(plaintext, 'utf8');
      let enc2 = cipher.final();
  
      return Buffer.concat([enc1, enc2, iv, cipher.getAuthTag()]).toString("base64");
    }
    catch (err) {
      console.log("AES: Encrypt Error for key " + key)
    }
    return null;
  },
  Decrypt(ciphertext, key) {
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
      console.log("AES: Decrypt Error for key " + key)
    }
    return null;
  }
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
    
    // POST without cookie
    .post("/agreementkey", async (req, res) => {
      try {
        let body = req.body
        let key = GetRandomString(32)

        await MongoClient.db("main").collection("userkeys").deleteMany( {  ip : req.ipInfo.ip})
        await MongoClient.db("main").collection("userkeys").insertOne( {  ip : req.ipInfo.ip,  key : AES.Encrypt(key, HashKey(req.ipInfo.ip, "authIP"))})
        console.log(`Create Key for ${req.ipInfo.ip} : ${key}`)
        return res.status(200).json({ key : RSA.Encrypt(key, crypto.createPublicKey(body.key)) })
 
      }
      catch (e) {
        console.error(e)
        return res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      }
    })
    //AES.Decrypt/Encrypt Init
    .post("/*", async (req, res, next) => {
      try {
        let findKey = await MongoClient.db("main").collection("userkeys").find({ ip : req.ipInfo.ip }).toArray()
        if (findKey.length != 0) {
          let key = AES.Decrypt(findKey[0].key, HashKey(findKey[0].ip, "authIP")) 
          console.log(`Found key for ${req.ipInfo.ip} : ${key}`)
          let decrypted = AES.Decrypt(req.body.data, key)
          if (!decrypted)
            return res.status(403).json({})
          req.body =  JSON.parse(decrypted)
          req.body = JSON.parse(req.body)
          req.key = key
          res.locals.json = function (obj) {
            return res.status(200).json({data : AES.Encrypt(JSON.stringify(obj), req.key)})
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
      try {
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
          if (data[0].hashedPassword == HashSHA3512(password)) {
            let device = {
              ip : req.ipInfo.ip,
              type : req.device.type,
            }

            device.location = await GetLocationFromIp(device.ip)
      
            console.log("Device Info", device)
            let code = GetRandomCode()

            console.log(`Generate PIN for ${username} : ${code}`)
            await MongoClient.db("main").collection("usercodes").insertOne(
              { username: username,
                code : AES.Encrypt(code, HashKey(req.ipInfo.ip, username) ),
                ip : device.ip,
                type : device.type,
                location : device.location,
                requestTime : Date.now() + 0,
                cookie : false
              })

            return res.locals.json({ code : code })
        
          }
          else 
            return res.status(406).json({ error : "Mật khẩu không đúng"})
        }
        else  return res.status(406).json({ error : "Tên tài khoản không tồn tại"})
      }
      catch (e) {
        console.error(e)
        return res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      } 
    })    
    .post("/getcookie" , async (req, res) => {
      let body = req.body;
      let code = (body.code || "").trim();

      console.log("Request Get Cookie From Code ", code);
      if (!code)
        return res.status(406).json({ error : "code không hợp lệ"});

      let data = await MongoClient.db("main").collection("usercodes").find({ip : req.ipInfo.ip, type : req.device.type}).toArray()
      for (let i = 0; i < data.length; i++) 
        if ( data[i].cookie && code == AES.Decrypt(data[i].code, HashKey(data[i].ip, data[i].username))) { 
          let cookie = AES.Decrypt(data[i].cookie, HashKey(data[i].ip, data[i].username))
          console.log("Get Cookie from Code", data)
          await MongoClient.db("main").collection("usercodes").deleteMany({code: AES.Encrypt(code, HashKey(data[i].ip, data[i].username)) , ip : req.ipInfo.ip, type : req.device.type})
          await MongoClient.db("main").collection("usercookies").insertOne( { username : data[i].username, cookie : AES.Encrypt(cookie, HashKey(data[i].ip, data[i].username)), ip : data[i].ip, canAuth : false, expire : Date.now() + 315619200000})
          console.log(`Create Cookie For User ${data[i].username} : ${cookie}`)

          return res.locals.json({cookie : cookie})
        }


      return res.status(406).json({ error : "Mã xác thực không hợp lệ hoặc chưa được cấp quyền"})
    })
    .post("/*", async (req, res, next) => {
      try {
        let ip = req.body.trust || req.ipInfo.ip
        let findUser = await MongoClient.db("main").collection("usercookies").find({  ip : ip, expire : { $gte: Date.now() }  }).toArray()

       for (let i = 0; i < findUser.length; i++) {
          if ( req.body.cookie == AES.Decrypt(findUser[i].cookie, HashKey(findUser[i].ip, findUser[i].username)) && ( ip != req.body.trust || findUser[i].canAuth)) {
            let username = findUser[0].username
            let canAuth = findUser[0].canAuth
            console.log(`Auth Success for user ${username}`)
            
            req.username = username
            req.canAuth = canAuth

            return next()
          }
        }

        return res.status(406).json({ error : "Phiên đăng nhập không hợp lệ"})
      }
      catch (e) {
        console.error(e)
        return res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      }        
    })
    .post("/getinfo" , async (req, res) => {
      try {
        if (!req.canAuth)
          return res.status(406).json({ error : "Thiết bị không có quyền xác minh"});

        let body = req.body;
        let code = (body.code || "").trim();

        console.log("Request Get Code Info ", code);
        if (!code)
          return res.status(406).json({ error : "code không hợp lệ"});

        let data = await MongoClient.db("main").collection("usercodes").find({username : req.username}).toArray()

        for (let i = 0; i < data.length; i++) 
          if (!data[i].cookie && code == AES.Decrypt(data[i].code, HashKey(data[i].ip, data[i].username))) { 
            delete data[i]._id
            data[i].requestTime = ToTickCSharp(data[i].requestTime)
            console.log(`Get info Auth Code`, data[i])  
            return res.locals.json(data[i]) 
          }

        return res.status(406).json({ error : "Mã xác thực bạn nhập không đúng"})
      }
      catch (e) {
        console.error(e)
        return res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      } 
   
    })
    .post("/confirm" , async (req, res) => {
      try {
        if (!req.canAuth)
          return res.status(406).json({ error : "Thiết bị không có quyền xác minh"});

        let body = req.body;
        let code = (body.code || "").trim();

        console.log("Confirm Auth ", code);
        if (!code)
          return res.status(406).json({ error : "code không hợp lệ"});

        let data = await MongoClient.db("main").collection("usercodes").find({username : req.username}).toArray()

        for (let i = 0; i < data.length; i++)
          if (!data[i].cookie && code == AES.Decrypt(data[i].code, HashKey(data[i].ip, data[i].username))) { 
            let cookie = GetRandomString(75)
            console.log("Get Cookie from Code", data[i])
            await MongoClient.db("main").collection("usercodes").updateOne({code: data[i].code, username : req.username}, {$set : {cookie : AES.Encrypt(cookie, HashKey(data[i].ip, data[i].username))}})
            return res.locals.json({message : "Đã cấp quyền thành công"}) 
          }

         return res.status(406).json({ error : "Mã xác thực bạn nhập không đúng"})
      }
      catch (e) {
        console.error(e)
        return res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      } 
    })
  
  .listen(PORT, () => console.info("WebApp" , `Listening on ${ PORT }`))



}


main();

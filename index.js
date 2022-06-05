/////////////////modules///////////////
const express = require('express');
const path = require('path'); 
const PORT = process.env.PORT || 5000
const app = express();
const MongoDB =  require('mongodb');
const bodyParser = require('body-parser');

c
const config = require('./config.json');
MongoClient = new MongoDB.MongoClient(encodeURI(config.mongodb) , { useUnifiedTopology: true } );
var ObjectId = MongoDB.ObjectId; 


async function GetRandomString(LENGTHTEXT)
{
  let codereturn = ''
  let textcache   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  for (let i = 1; i<= LENGTHTEXT ; i++)
  codereturn  += textcache.charAt(Math.floor(Math.random() *textcache.length))
  return codereturn;
}


async function GetRandomToken() {
  let token = await GetRandomString(75);
  let checkToken = await MongoClient.db("main").collection("token").find({ token : token });
  if (checkToken.length > 0) return GetRandomToken();

  return token;
}

async function GetUserDataFromToken(token) {
  if (!token) return;
  let checkToken = await MongoClient.db("main").collection("token").find({ token : token, expires: { $gt: Date.now() } }).toArray();
  if (checkToken.length == 0) return;
  let checkData = await MongoClient.db("main").collection("account").find({ username : checkToken[0].username}).toArray();
  if (checkData.length == 0)  return;
  return checkData[0]
}

function ToTickCSharp(timestamp) {
  return (timestamp * 10000) + 621355968000000000
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
    .post("/login", async (req, res) => {
      try {
        let username = (req.body.username || "").trim().toLowerCase();
        let password = (req.body.password || "").trim();

        let data = await MongoClient.db("main").collection("account").find({username: username, password: password}).toArray()
        if (data.length > 0) {
          let token = await GetRandomToken()
          await MongoClient.db("main").collection("token").deleteMany({username: username})
          MongoClient.db("main").collection("token").insertOne({username: username, token: token, expires: Date.now()  + 24*60*60*1000 })
          console.log(`Create Token: ${token} for user ${username}`)
          return res.status(200).json({ token : token})
        }

        return res.status(200).json({ token : ""})
      }
      catch (e) {
        console.error(e)
        return res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      }
    })
    .post("/signup" , async (req, res) => {
      let body = req.body;
      body.username = (body.username || "").trim().toLowerCase();
      body.password = (body.password || "").trim();
      body.createdOn = Date.now();

      
      if (!body.username)
        return res.status(406).json({ error : "Username không hợp lệ"});

      if (!body.password)
        return res.status(406).json({ error : "Password không hợp lệ"});
    

      let data = await MongoClient.db("main").collection("account").find({username: body.username}).toArray()
      if (data.length == 0) {
        MongoClient.db("main").collection("account").insertOne(body)
        console.log(`Create Token: username ${body.username} for person name ${body.fullname}`)
        return res.status(200).json({ message : "Bạn đã tạo tài khoản thành công"})
      }
      else  return res.status(200).json({ message : "Tên tài khoản đăng nhập hiện đã có vui lòng chọn tên khác"})
    })
    /// POST with Token
    .post("/*", async (req, res, next) => {
      try {
        let token = req.headers['token-user']
        let userData = await GetUserDataFromToken(token)
        if (userData) {
          req.userData = userData
          console.log("Authenticated: ", userData)
          next();
        }
          
        else
          res.status(401).json({ error: "Phiên đăng nhập không hợp lệ"});
      }
      catch (e) {
        console.error(e)
        res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      }
    })
    // GET MAIN CLASS
    .post("/account", async (req, res) => {
      try {
        let data = req.userData
        delete data.password;
        delete data._id;
        console.log("Get Account: ", data)
        data.createdOn = ToTickCSharp(data.createdOn)
        res.status(200).json(data);
      }
      catch (e) {
        console.error(e)
        res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      }
    })
    .post("/wallets", async (req, res) => {
      try {
        let username = req.userData.username
        let data = await MongoClient.db("main").collection("wallet").find({username: username}).toArray()

        for (let i = 0; i < data.length; i++) {
          data[i].id = data[i]._id.toString()
          data[i].createdOn = ToTickCSharp(data[i].createdOn)
        }
        
        console.log(data)
        res.status(200).json(data);
      }
      catch (e) {
        console.error(e)
        res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
      }
    })
    // Some action
    .post("/editaccount", async (req, res) =>  {
    try {
      let data = req.userData
      delete data._id 
        
      let body = req.body

      data.password = (body.password || '').trim().toLowerCase() || data.password
      data.fullname = body.fullname || data.fullname
      data.phone = body.phone || data.phone
      data.address = body.address || data.address

      delete data.token

      console.log("Update Account: ", data )
      await MongoClient.db("main").collection("account").updateOne({username : data.username},{$set: data})   
      res.status(200).json({"message" : "Cập nhật thông tin thành công"});
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  .post("/createwallet", async (req, res) =>  {
    try {
      let userData = req.userData 
      let walletName = req.body.walletName
      let type = req.body.type
      
      if (!walletName)
        return res.status(200).json({ message : "Tên ví không hợp lệ"});
    
      if (!type)
        return res.status(200).json({ message : "Loại ví không hợp lệ"});
    
      let checkWallets = await MongoClient.db("main").collection("wallet").find({ username: userData.username, walletName : walletName}).toArray()
      
      if (checkWallets.length != 0) 
        return res.status(200).json({"message": "Tên ví đã tồn tại vui lòng chọn tên khác"})

      await MongoClient.db("main").collection("wallet").insertOne({
        username: userData.username,
        walletName: walletName,
        type: type,
        balance: 0,
        createdOn: Date.now()
      })

      console.log("Create new Wallet: ", req.body)
      res.status(200).json({"message" : `Ví ${walletName} đã được khởi tạo thành công`});
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  // In Wallet
  .post("/wallet/*", async (req, res, next) =>  {
    try {
      let userData = req.userData
      let walletData = await MongoClient.db("main").collection("wallet").find( { _id : ObjectId(req.body.walletId), username : userData.username }).toArray()

      if (walletData.length == 0)
        return res.status(200).json({ message : "Ví bạn không tồn tại vui lòng thoát ra và thử lại thao tác"})

      console.log("Wallet: ", walletData)
      req.walletData = walletData[0]
      next()
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  .post("/wallet/edit", async (req, res) => {
    try {
      let username = req.userData.username
      let walletData = req.walletData
      let new_walletName = req.body.walletName.trim()
      let new_type = req.body.type.trim()

      if (!new_walletName)
        return res.status(200).json({ message : "Tên ví bạn nhập không hợp lệ"})

      if (!new_type)
        return res.status(200).json({ message : "Loại ví bạn nhập không hợp lệ"})

      if (walletData.walletName != new_walletName) {
        let checkWallet = await MongoClient.db("main").collection("wallet").find( {username : username, walletName : new_walletName}).toArray()

        if (checkWallet.length > 0)
          return res.status(200).json({ message : "Tên ví đã tồn tại vui lòng chọn tên ví khác"})  
      }

      walletData.walletName = new_walletName
      walletData.type = new_type

      await MongoClient.db("main").collection("wallet").updateOne( { _id : walletData._id} , {$set : walletData})

      console.log(`Edit Wallet Info `, walletData)
      res.status(200).json({message: `Lệnh nạp tiền vào ví ${walletData.walletName} đã được thực hiện`});
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  .post("/wallet/deposit", async (req, res) => {
    try {
      let username = req.userData.username
      let walletData = req.walletData
      let amount = parseInt(req.body.amount)
      let info = req.body.info

      if (amount < 0)
        return res.status(200).json({ message : "Số tiền không hợp lệ"})

      await MongoClient.db("main").collection("wallet").updateOne( { _id : walletData._id}, {$set : { balance : walletData.balance + amount} })
      await MongoClient.db("main").collection("transaction").insertOne( { username : username, walletName : walletData.walletName, amount : amount, info : info, createdOn : Date.now() })

      console.log(`Deposit ${amount} VND with Info "${info}"`)
      res.status(200).json({message: `Lệnh nạp tiền vào ví ${walletData.walletName} đã được thực hiện`});
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  .post("/wallet/withdraw", async (req, res) => {
    try {
      let username = req.userData.username
      let walletData = req.walletData
      let amount = parseInt(req.body.amount)
      let info = req.body.info

      if (amount < 0)
        return res.status(200).json({ message : "Số tiền không hợp lệ"})

      if (amount > walletData.balance)
        return res.status(200).json({message: `Số tiền trong ví không đủ để thực hiện lệnh rút`});

      await MongoClient.db("main").collection("wallet").updateOne( { _id : walletData._id}, {$set : { balance : walletData.balance - amount} })
      await MongoClient.db("main").collection("transaction").insertOne( { username : username, walletName : walletData.walletName, amount : -amount, info : info, createdOn : Date.now() })

      console.log(`Withdraw ${amount} VND with Info "${info}"`)
      res.status(200).json({message: `Lệnh rút tiền ra ví ${walletData.walletName} đã được thực hiện`});
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  .post("/wallet/createloan", async (req, res) => {
    try {
      let username = req.userData.username
      let walletData = req.walletData
      let amount = parseInt(req.body.amount)
      let debtor = req.body.debtor
      let info = req.body.info

      if (amount < 0)
        return res.status(200).json({ message : "Số tiền không hợp lệ"})


      if (amount > walletData.balance)
        return res.status(200).json({message: `Số tiền trong ví không đủ để thực hiện lệnh cho vay`});

      await MongoClient.db("main").collection("wallet").updateOne( { _id : walletData._id}, {$set : { balance : walletData.balance - amount} })
      await MongoClient.db("main").collection("transaction").insertOne( { username : username, walletName : walletData.walletName, amount : -amount, info : `Khoảng Cho Vay của ${debtor}`, createdOn : Date.now() })
      await MongoClient.db("main").collection("loan").insertOne( {  username : username, walletName : walletData.walletName, debtor : debtor, amount : amount, info : info, createdOn : Date.now() })

      console.log(`Create Loan ${amount} VND with Info "${info}"`)
      res.status(200).json({message: `Lệnh cho vay từ ví ${walletData.walletName} đã được thực hiện`});
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  .post("/wallet/createdebt", async (req, res) => {
    try {
      let username = req.userData.username
      let walletData = req.walletData
      let amount = parseInt(req.body.amount)
      let lender = req.body.lender
      let info = req.body.info

      if (amount < 0)
        return res.status(200).json({ message : "Số tiền không hợp lệ"})

      await MongoClient.db("main").collection("wallet").updateOne( { _id : walletData._id}, {$set : { balance : walletData.balance + amount} })
      await MongoClient.db("main").collection("transaction").insertOne( { username : username, walletName : walletData.walletName, amount : amount, info : `Khoảng Vay từ ${lender}`, createdOn : Date.now() })
      await MongoClient.db("main").collection("debt").insertOne( {  username : username, walletName : walletData.walletName, lender : lender, amount : amount, info : info, createdOn : Date.now() })

      console.log(`Create Debt ${amount} VND with Info "${info}"`)
      res.status(200).json({message: `Lệnh vay cho ví ${walletData.walletName} đã được thực hiện`});
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  .post("/wallet/payloan", async (req, res) => {
    try {
      let username = req.userData.username
      let walletData = req.walletData
      let loanId = req.body.loanId;

      let loanData = await MongoClient.db("main").collection("loan").find({_id: ObjectId(loanId)}).toArray()

      if (loanData.length == 0)
        return res.status(200).json({ message: "Khoảng cho vay không tồn tại"})

      loanData = loanData[0]

      if (loanData.username != username || loanData.walletName != walletData.walletName)
        return res.status(200).json({ message: "Khoảng cho vay không khớp với ví hoặc tài khoản này"})
      
      if (loanData.isPaymented)
        return res.status(200).json({ message: "Khoảng cho vay này đã được thu từ trước"})
      
      await MongoClient.db("main").collection("wallet").updateOne( { _id : walletData._id}, {$set : { balance : walletData.balance + loanData.amount} })
      await MongoClient.db("main").collection("transaction").insertOne( { username : username, walletName : walletData.walletName, amount : loanData.amount, info : `Thu Khoảng Vay từ ${loanData.debtor}`, createdOn : Date.now() })
      await MongoClient.db("main").collection("loan").updateOne({_id : loanData._id}, {$set: { isPaymented : true, paymentedOn: Date.now()}})

      console.log(`Pay Loan ${loanData.amount} VND with Info "${loanData.info}"`)
      res.status(200).json({message: `Lệnh thu nợ cho ví ${walletData.walletName} đã được thực hiện`});
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  .post("/wallet/paydebt", async (req, res) => {
    try {
      let username = req.userData.username
      let walletData = req.walletData
      let debtId = req.body.debtId;

      let debtData = await MongoClient.db("main").collection("debt").find({_id: ObjectId(debtId)}).toArray()

      if (debtData.length == 0)
        return res.status(200).json({ message: "Khoảng vay không tồn tại"})

      debtData = debtData[0]

      if (debtData.username != username || debtData.walletName != walletData.walletName)
        return res.status(200).json({ message: "Khoảng vay không khớp với ví hoặc tài khoản này"})
      
      if (debtData.isPaymented)
        return res.status(200).json({ message: "Khoảng vay này đã được trả từ trước"})
      
      if (debtData.amount > walletData.balance)
        return res.status(200).json({message: `Số tiền trong ví không đủ để thực hiện lệnh trả nợ`});

      await MongoClient.db("main").collection("wallet").updateOne( { _id : walletData._id}, {$set : { balance : walletData.balance - debtData.amount} })
      await MongoClient.db("main").collection("transaction").insertOne( { username : username, walletName : walletData.walletName, amount : -debtData.amount, info : `Trả Khoảng Vay của ${debtData.lender}`, createdOn : Date.now() })
      await MongoClient.db("main").collection("debt").updateOne({_id : debtData._id}, {$set: { isPaymented : true, paymentedOn: Date.now()}})

      console.log(`Pay Debt ${debtData.amount} VND with Info "${debtData.info}"`)
      res.status(200).json({message: `Lệnh trả nợ của ví ${walletData.walletName} đã được thực hiện`});
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  .post("/wallet/load", async (req, res) => {
    try {
      let data = req.walletData
      data.id = data._id.toString()
      console.log(`sync new Data`)
      res.status(200).json(data);
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  .post("/wallet/transactions", async (req, res) => {
    try {
      let username = req.userData.username
      let walletName = req.walletData.walletName
      let data = await MongoClient.db("main").collection("transaction").find({username: username, walletName : walletName }).toArray()

      for (let i = 0; i < data.length; i++) {
        data[i].id = data[i]._id.toString()
        data[i].createdOn = ToTickCSharp(data[i].createdOn)
      }

  
      console.log(data)
      res.status(200).json(data);
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  .post("/wallet/loans", async (req, res) => {
    try {
      let username = req.userData.username
      let walletName = req.walletData.walletName
      let data = await MongoClient.db("main").collection("loan").find({username: username, walletName : walletName}).toArray()

      for (let i = 0; i < data.length; i++) {
        data[i].id = data[i]._id.toString()
        data[i].createdOn = ToTickCSharp(data[i].createdOn)
        if (data[i].paymentedOn)
          data[i].paymentedOn = ToTickCSharp(data[i].paymentedOn)
      }


      console.log(data)
      res.status(200).json(data);
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })
  .post("/wallet/debts", async (req, res) => {
    try {
      let username = req.userData.username
      let walletName = req.walletData.walletName
      let data = await MongoClient.db("main").collection("debt").find({username: username, walletName : walletName}).toArray()

      for (let i = 0; i < data.length; i++) {
        data[i].id = data[i]._id.toString()
        data[i].createdOn = ToTickCSharp(data[i].createdOn)
        if (data[i].paymentedOn)
          data[i].paymentedOn = ToTickCSharp(data[i].paymentedOn)
      }

      console.log(data)
      res.status(200).json(data);
    }
    catch (e) {
      console.error(e)
      res.status(406).json({ error : "Có lỗi phát sinh trên máy chủ. Vui lòng thử lại"});
    }
  })


  .listen(PORT, () => console.info("WebApp" , `Listening on ${ PORT }`))



}



main();

const express = require('express')
const port = 9000
require('dotenv').config()
const cookieParser = require("cookie-parser");
const cors = require("cors");
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "http://localhost:3000", // Allow frontend URL
    credentials: true, // Required for cookies to be sent
  })
);



const crypto = require("crypto");
const SECRET_KEY = `${process.env.PSECRETKEY}`; // Must be 16 bytes

const nodemailer = require("nodemailer");

const { v4: uuidv4 } = require('uuid');

const bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');

const multer  = require('multer')

const uploadpath = "public/uploads";

const mystorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadpath)
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + file.originalname)
  }
})


const upload = multer({ storage: mystorage })

const fs = require("fs");

const mongoose = require('mongoose');

mongoose.connect('mongodb+srv://shopappdbuser:Passw123@cluster0.oapfi.mongodb.net/shopappdb?retryWrites=true&w=majority&appName=Cluster0').then(()=> 
  {
    console.log("Connected to MongoDB"); 
  }).catch((err) => 
  {
    console.log("Error while connecting " + err);
  })
  

// mongoose.connect('mongodb://127.0.0.1:27017/shopappdb').then(()=> 
// {
//   console.log("Connected to MongoDB"); 
// }).catch((err) => 
// {
//   console.log("Error while connecting " + err);
// })

const transporter = nodemailer.createTransport({
  host: "smtp.hostinger.com",
  port: 465,
  secure: true, // true for port 465, false for other ports
  auth: {
    user : `${process.env.SMTP_UNAME}`,
    pass : `${process.env.SMTP_PASS}`
  },
});

function verifytoken(req,res,next)
{
  const token = req.cookies.authToken;
  console.log(token)
  if (!token) return res.status(401).json({ code: 0, message: "Unauthorized User" });
  try 
  {
    const decoded = jwt.verify(token, process.env.TSECRETKEY);
    req.user = decoded; // Attach decoded user data to request
    next();
  } 
  catch (error) 
  {
    res.status(401).json({ code: 0, message: "Invalid Token" });
  }
}

// function verifytoken(req,res,next)
// {
//   if(!req.headers.authorization)
//   {
//     return res.status(401).send('Unauthorized Subject')
//   }
//   let token = req.headers.authorization.split(' ')[1]
//   if(token=='null')
//   {
//     return res.status(401).send('Unauthorized request')
//   }

//   try 
//   {
//     const payload = jwt.verify(token, process.env.TSECRETKEY);
//     console.log(payload)
//     if(!payload)
//     {
//       return res.status(401).send('Unauthorized Request')
//     }
//     req.user = payload;//id,role
//     next();
//   } 
//   catch (err) 
//   {
//     res.status(400).json({ message: "Invalid Token" });
//   }
// }


const verifyAdmin = (req, res, next) => 
{
  if (req.user.role !== "admin") 
  {
    return res.status(403).json({ message: "Access Denied: Admins only" });
  }
  else
  {
    next();
  }
};

var signupSchema = mongoose.Schema({name:String,phone:String,username:{type:String,unique:true},password:String,usertype:String, isActivated:Boolean,token:String},{versionKey:false})

const RegisterModel = mongoose.model('Signup',signupSchema,"Signup");  //modelname,schema,collection name


const hexToBuffer = (hex) =>
  Buffer.from(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

// Decrypt function
const decryptPassword = (encryptedData, iv) => 
{
  const decipher = crypto.createDecipheriv("aes-128-cbc", Buffer.from(SECRET_KEY), hexToBuffer(iv));
  let decrypted = decipher.update(hexToBuffer(encryptedData));
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
};

app.post("/api/register",async(req,res)=>
{
  try
  {
    const { pass, iv } = req.body;
    const decryptedPassword = decryptPassword(pass, iv);
    
    const hash = bcrypt.hashSync(decryptedPassword, 10);
    const acttoken=uuidv4();
    const newRecord = new RegisterModel({name:req.body.pname,phone:req.body.phone,username:req.body.username,password:hash, usertype:"normal",isActivated:false,token:acttoken});
    const result = await newRecord.save();
    if(result)
    {
      const mailOptions = 
      {
        from: 'class@gtbinstitute.com',
        to: req.body.username,
        subject: 'Account Activation Mail from ShoppingPoint.com',
        html: `Dear ${req.body.pname}<br/><br/>Thanks for signing up on our website. You can activate your account by clicking on the following link:-<br/><br/> <a href='http://localhost:3000/activate?token=${acttoken}'>Acivate Account</a><br/><br/>Team ShoppingPoint.com`
      };
      transporter.sendMail(mailOptions, (error, info) => 
      {
        if (error) 
        {
          res.send({code:2})
          console.log(error);
          res.send('Error sending email');
        } 
        else 
        {
          console.log('Email sent: ' + info.response);
          res.send({code:1})
        }
      });
    }
    else
    {
      res.json({code:0})
    }
  }
  catch(e)
  {
    res.send({code:-1,errmsg:e.message})
    console.log(e.message);
  }
})

app.post("/api/createadmin",verifytoken,async(req,res)=>
  {
    try
    {
       // newRecord.save().then(() => res.send({msg:"Signup Successfull"})).catch(()=>res.send({msg:"Error while signing up"}));
       const hash = bcrypt.hashSync(req.body.pass, 10);
      const newRecord = new RegisterModel({name:req.body.pname,phone:req.body.phone,username:req.body.username,password:hash, usertype:"admin"});
  
      const result = await newRecord.save();
      if(result)
      {
        res.send({code:1})
      }
      else
      {
        res.json({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
      console.log(e.message);
    }
  })

// app.post("/api/login",async(req,res)=>
// {
//   try
//   {
//     const result = await RegisterModel.findOne({username:req.body.uname});
//     // const result2 = await RegisterModel.findOne({username:req.params.un}).select("-password").select("-phone").select("-_id");
//     if(result)
//     {
//       if(bcrypt.compareSync(req.body.pass, result.password))
//       {
//         const respdata = {id:result._id,name:result.name,username:result.username,usertype:result.usertype,isActivated:result.isActivated}
//         let jtoken = jwt.sign({id: result._id,role:result.usertype}, process.env.TSECRETKEY , { expiresIn: '1h' });
//         res.send({code:1,membdata:respdata,jstoken:jtoken})
//       }
//       else
//       {
//         res.send({code:0})
//       }
//     }
//     else
//     {
//       res.send({code:0})
//     }
//   }
//   catch(e)
//   {
//     res.send({code:-1,errmsg:e.message})
//   }
// })

app.post("/api/login", async (req, res) => {
  try {
    const result = await RegisterModel.findOne({ username: req.body.uname });
    if (result) {
      if (bcrypt.compareSync(req.body.pass, result.password)) {
        const respdata = { id: result._id, name: result.name, username: result.username, usertype: result.usertype, isActivated: result.isActivated };
        let jtoken = jwt.sign({ id: result._id, role: result.usertype }, process.env.TSECRETKEY, { expiresIn: "1h" });

        res.cookie("authToken", jtoken, {
          httpOnly: true,  // Prevent JavaScript access
          secure: false,   // Set to false in development
          sameSite: "Lax", // Helps with CSRF protection, but allows cross-origin navigation
          maxAge: 3600000, // 1 hour expiration
        });
        // console.log("Cookie Set:", res.getHeaders()["set-cookie"]);
        res.send({ code: 1, membdata: respdata });
      } else {
        res.send({ code: 0 });
      }
    } else {
      res.send({ code: 0 });
    }
  } catch (e) {
    res.send({ code: -1, errmsg: e.message });
  }
});

app.post("/api/logout", (req, res) => 
{
  res.clearCookie("authToken");
  res.json({ code: 1, message: "Logged out successfully" });
});
app.get("/api/fetchudetailsbyid",async(req,res)=>
  {
    try
    {
      const result = await RegisterModel.findOne({_id:req.query.id});
      if(result)
      {
          const respdata = {id:result._id,name:result.name,username:result.username,usertype:result.usertype}
          let jtoken = jwt.sign({ id: result._id, role: result.usertype }, process.env.TSECRETKEY, { expiresIn: "1h" });
          res.cookie("authToken", jtoken, {
            httpOnly: true,  // Prevent JavaScript access
            secure: false,   // Set to false in development
            sameSite: "Lax", // Helps with CSRF protection, but allows cross-origin navigation
            maxAge: 3600000, // 1 hour expiration
          });

          res.send({code:1,membdata:respdata})
      }
      else
      {
        res.send({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
    }
  })

var resetPasswordSchema = new mongoose.Schema({username:String,token:String,exptime:String}, { versionKey: false } );
var resetpassModel = mongoose.model("resetpass",resetPasswordSchema,"resetpass");
  
app.get('/api/forgotpass/:uname', async (req, res) => 
{
  try
  {
    const userdata = await RegisterModel.findOne({ username: req.params.uname });
    if (!userdata) 
    {
      return res.send({code:0});
    }
    else
    {
      var resettoken = uuidv4();
      var minutesToAdd=15;
      var currentDate = new Date();//current date and time
      var futureDate = new Date(currentDate.getTime() + minutesToAdd*60000);//current millsecs+15 mins millsecs
  
      var newreset = new resetpassModel({username:req.params.uname,token:resettoken,exptime:futureDate});
      let saveresult = await newreset.save();
  
      if(saveresult)
      {
        const mailOptions = 
        {
          from: 'class@gtbinstitute.com',
          to: req.params.uname,
          subject: 'Reset your password::ShoppingPoint.com',
          html: `Hi ${userdata.name},<br/><br/> Please click on the following link to reset your password: <br/><br/>
          <a href='http://localhost:3000/resetpassword?token=${resettoken}'>Reset Password</a>`
        };
        // Use the transport object to send the email
        transporter.sendMail(mailOptions, (error, info) => 
        {
          if (error) 
          {
            console.log(error);
            res.status(200).send({code:2});
          } 
          else 
          {
            console.log('Email sent: ' + info.response);
            res.status(200).send({code:1});
          }
        });
      }
      else
      {
        res.send({msg:"Error, try again"});
      }
    }
  }
  catch(e)
  {
    res.send({code:-1,errmsg:e.message})
  }
});

app.get("/api/checktoken",async(req,res)=>
  {
    try
    {
      const result = await resetpassModel.findOne({token:req.query.token})
      if(result)
      {
        const currtime = new Date();
        const exptime = new Date(result.exptime);
        if(currtime<exptime)
        {
          res.send({code:1,passdata:result})
        }
        else
        {
          res.send({code:2})
        }
      }
      else
      {
        res.send({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
    }
  })

  app.put("/api/resetpass",async(req,res)=>
  {
    try
    {
      const hash = bcrypt.hashSync(req.body.newpass, 10);
      const result = await RegisterModel.updateOne({username:req.body.uname},{password:hash})
      if(result.modifiedCount===1)
      {
        res.send({code:1})
      }
      else
      {
        res.send({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
    }
  })
app.put("/api/changepass",verifytoken,async(req,res)=>
{
  try
  {
    const result = await RegisterModel.findOne({username:req.body.uname})
    if(result)
    {
      if(bcrypt.compareSync(req.body.currpass, result.password))
      {
        const hash = bcrypt.hashSync(req.body.newpass, 10);
        const result2 = await RegisterModel.updateOne({username:req.body.uname},{password:hash})
        if(result2.modifiedCount===1)
        {
          res.send({code:1})
        }
      }
      else
      {
        res.send({code:2})
      }
    }
    else
    {
      res.send({code:0})
    }
  }
  catch(e)
  {
    res.send({code:-1,errmsg:e.message})
  }
})

app.get("/api/searchuser",verifytoken,verifyAdmin,async(req,res)=>
  {
    try
    {
      const result = await RegisterModel.findOne({username:req.query.un}).select("-password").select("-_id")
      if(result)
      {
        res.send({code:1,membdata:result})
      }
      else
      {
        res.send({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
    }
  })

  app.get("/api/getallusers",async(req,res)=>
  {
    try
    {
      const result = await RegisterModel.find({usertype:"normal"}).select("-password")
      if(result.length>0)
      {
        res.send({code:1,membsdata:result})
      }
      else
      {
        res.send({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
    }
  })


app.delete("/api/deluser",async(req,res)=>
{
  try
  {
    const result = await RegisterModel.deleteOne({_id:req.query.uid})
    console.log(result)
    if(result.deletedCount===1)
    {
      res.send({code:1})
    }
    else
    {
      res.send({code:0})
    }
  }
  catch(e)
  {
    res.send({code:-1,errmsg:e.message})
  }
})

var catSchema = mongoose.Schema({catname:String,catpic:String,disporder:Number},{versionKey:false})
const CatModel = mongoose.model('category',catSchema,"category");  //modelname,schema,collection name
app.post("/api/savecategory",upload.single('cpic'),async(req,res)=>
{
  try
  {
    var picname="nopic.png";
    if(req.file)
    {
        picname=req.file.filename;
    }

    const newRecord = new CatModel({catname:req.body.cname,catpic:picname,disporder:req.body.disporder});
    const result = await newRecord.save();
    if(result)
    {
      res.send({code:1})
    }
    else
    {
      res.json({code:0})
    }
  }
  catch(e)
  {
    res.send({code:-1,errmsg:e.message})
    console.log(e);
  }
})

app.get("/api/getallcat",async(req,res)=>
  {
    try
    {
      const result = await CatModel.find().sort({"disporder":1})
      if(result.length>0)
      {
        res.send({code:1,catdata:result})
      }
      else
      {
        res.send({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
    }
  })

  app.delete("/api/delcat",async(req,res)=>
  {
    try
    {
      const result = await CatModel.deleteOne({_id:req.query.cid})
      console.log(result)
      if(result.deletedCount===1)
      {
        res.send({code:1})
      }
      else
      {
        res.send({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
    }
  })

  app.put("/api/updatecat",upload.single('cpic'),async(req,res)=>
  {
    try
    {
      var picname;
      if(req.file) // it shows that there is a file in the request and admin wants to change the image
      {
          picname=req.file.filename;
          if(req.body.oldpicname!=="nopic.png")
          {
            fs.unlinkSync(`${uploadpath}/${req.body.oldpicname}`);
          }
      }
      else
      {
        picname=req.body.oldpicname;
      }
      const result = await CatModel.updateOne({_id:req.body.cid},{catname:req.body.cname,catpic:picname,disporder:req.body.disporder})
      console.log(result)
      if(result.modifiedCount===1)
      {
        res.send({code:1})
      }
      else
      {
        res.send({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
    }
  })


  var subCatSchema = mongoose.Schema({catid: { type: mongoose.Schema.Types.ObjectId, ref: 'category' },subcatname:String,subcatpic:String,disporder:Number},{versionKey:false})
  //ObjectId refers to the _id column of the given model


  const SubCatModel = mongoose.model('subcategory',subCatSchema,"subcategory");  //modelname,schema,collection name
  app.post("/api/savesubcategory",upload.single('scpic'),async(req,res)=>
  {
    try
    {
      var picname="nopic.png";
      if(req.file)
      {
          picname=req.file.filename;
      }
  
      const newRecord = new SubCatModel({catid:req.body.cid,subcatname:req.body.scname,subcatpic:picname,disporder:req.body.disporder});
      const result = await newRecord.save();
      if(result)
      {
        res.send({code:1})
      }
      else
      {
        res.json({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
      console.log(e);
    }
  })

  // app.get("/api/getsubcatbycatid/:cid",async(req,res)=>
  //   {
  //     try
  //     {
  //       const result = await SubCatModel.find({catid:req.params.cid})
  //       if(result.length>0)
  //       {
  //         res.send({code:1,subcatdata:result})
  //       }
  //       else
  //       {
  //         res.send({code:0})
  //       }
  //     }
  //     catch(e)
  //     {
  //       res.send({code:-1,errmsg:e.message})
  //     }
  //   })

  app.get("/api/getsubcatbycatid/:cid", async (req, res) => 
  {
    try 
    {
      // Find subcategories and populate the related category
      const result = await SubCatModel.find({ catid: req.params.cid }).populate('catid', 'catname')
      // Populate catid field, fetching only the catname
      console.log(result);
      if (result.length > 0) 
      {
        res.send({ code: 1, subcatdata: result });
      } 
      else 
      {
        res.send({ code: 0, message: "No subcategories found" });
      }
    } 
    catch (e) 
    {
      res.send({ code: -1, errmsg: e.message });
    }
  });

  app.put("/api/updatesubcat",upload.single('scpic'),async(req,res)=>
  {
    try
    {
      var picname;
      if(req.file) // it shows that there is a file in the request and admin wants to change the image
      {
          picname=req.file.filename;
          if(req.body.oldpicname!=="nopic.png")
          {
            fs.unlinkSync(`${uploadpath}/${req.body.oldpicname}`);
          }
      }
      else
      {
        picname=req.body.oldpicname;
      }
      const result = await SubCatModel.updateOne({_id:req.body.scid},{catid:req.body.cid,subcatname:req.body.scname,subcatpic:picname,disporder:req.body.disporder})
      console.log(result)
      if(result.modifiedCount===1)
      {
        res.send({code:1})
      }
      else
      {
        res.send({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
    }
  })



var prodSchema = mongoose.Schema({catid: { type: mongoose.Schema.Types.ObjectId, ref: 'category' }, subcatid: { type: mongoose.Schema.Types.ObjectId, ref: 'subcategory' },prodname:String,description:String,Rate:Number,Discount:Number,Stock:Number,featured:String,picture:String,addedon:String},{versionKey:false})

const ProdModel = mongoose.model('product',prodSchema,"product");  //modelname,schema,collection name

app.post("/api/saveproduct",upload.single('ppic'),async(req,res)=>
  {
    try
    {
      var picname="nopic.png";
      if(req.file)
      {
          picname=req.file.filename;
      }
  
      const newRecord = new ProdModel({catid:req.body.cid,subcatid:req.body.scid,prodname:req.body.pname,description:req.body.description,Rate:req.body.rate,Discount:req.body.dis,Stock:req.body.stock,featured:req.body.feat,picture:picname,addedon:new Date()});

      const result = await newRecord.save();
      if(result)
      {
        res.send({code:1})
      }
      else
      {
        res.json({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
      console.log(e);
    }
  })

app.get("/api/getprodsbysubcat/:scid",async(req,res)=>
  {
    try
    {
      const result = await ProdModel.find({subcatid:req.params.scid}).populate('subcatid catid','subcatname catname')
      if(result.length>0)
      {
        res.send({code:1,productsdata:result})
      }
      else
      {
        res.send({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
    }
  })

  app.get("/api/getproddetails/:pid",async(req,res)=>
    {
      try
      {
        const result = await ProdModel.findOne({_id:req.params.pid}).populate('subcatid catid','subcatname catname')
        if(result)
        {
          res.send({code:1,proddata:result})
        }
        else
        {
          res.send({code:0})
        }
      }
      catch(e)
      {
        res.send({code:-1,errmsg:e.message})
      }
    })

  app.put("/api/updateproduct",upload.single('ppic'),async(req,res)=>
  {
    try
    {
      var picname;
      if(req.file) // it shows that there is a file in the request and admin wants to change the image
      {
          picname=req.file.filename;
          if(req.body.oldpicname!=="nopic.png")
          {
            fs.unlinkSync(`${uploadpath}/${req.body.oldpicname}`);
          }
      }
      else
      {
        picname=req.body.oldpicname;
      }
      const result = await ProdModel.updateOne({_id:req.body.pid},{catid:req.body.cid,subcatid:req.body.scid,prodname:req.body.pname,description:req.body.description,Rate:req.body.rate,Discount:req.body.dis,Stock:req.body.stock,featured:req.body.feat,picture:picname})
      console.log(result)
      if(result.modifiedCount===1)
      {
        res.send({code:1})
      }
      else
      {
        res.send({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
    }
  })

var cartSchema = mongoose.Schema({prodid: { type: mongoose.Schema.Types.ObjectId, ref: 'product' },picture:String,prodname:String,rate:Number,qty:Number,totalcost:Number,username:String},{versionKey:false})

const CartModel = mongoose.model('cart',cartSchema,"cart");  //modelname,schema,collection name

app.post("/api/addtocart",async(req,res)=>
{
  try
  {
    const result1 = await CartModel.findOne({prodid:req.body.prodid,username:req.body.uname});
    if(result1)
    {
      const newqty = Number(result1.qty)+Number(req.body.qty);//oldqty+newqty
      const newtotalcost = Number(req.body.rate)*Number(newqty);
      const updateresult = await CartModel.updateOne({prodid:req.body.prodid,username:req.body.uname},{qty:newqty,totalcost:newtotalcost})
      if(updateresult.modifiedCount===1)
      {
        res.send({code:1})
      }
      else
      {
        res.send({code:0})
      }
    }
    else
    {
      const newRecord = new CartModel({prodid:req.body.prodid,picture:req.body.pic,prodname:req.body.pname,rate:req.body.rate,qty:req.body.qty,totalcost:req.body.tc,username:req.body.uname});

      const result2 = await newRecord.save();
      if(result2)
      {
        res.send({code:1})
      }
      else
      {
        res.json({code:0})
      }
    }
   
  }
  catch(e)
  {
    res.send({code:-1,errmsg:e.message})
  }
})

app.get("/api/getusercart/:uname", async (req, res) => 
{
  try 
  {
    const result = await CartModel.find({ username:req.params.uname })
    if (result.length > 0) 
    {
      res.send({ code: 1, usercart: result });
    } 
    else 
    {
      res.send({ code: 0});
    }
  } 
  catch (e) 
  {
    res.send({ code: -1, errmsg: e.message });
  }
});

app.delete("/api/delcartitem",async(req,res)=>
  {
    try
    {
      const result = await CartModel.deleteOne({_id:req.query.id})
      console.log(result)
      if(result.deletedCount===1)
      {
        res.send({code:1})
      }
      else
      {
        res.send({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
    }
  })

var orderSchema = mongoose.Schema({username:String,address:String,pmode:String,cardetails:Object,orderdt:Date,billamt:Number,items:[Object],status:String},{versionKey:false})

const OrderModel = mongoose.model('order',orderSchema,"order");  //modelname,schema,collection name

app.post("/api/saveorder",async(req,res)=>
  {
    try
    {
      var orditems = req.body.orderitems;
      for(var x=0;x<orditems.length;x++)
      {
        const updateresult = await ProdModel.updateOne({_id:orditems[x].prodid},{$inc:{"Stock":-orditems[x].qty}})
      }

      const currentDateUTC = new Date(); // Get the current date in UTC
      const ISTOffset = 5.5 * 60 * 60 * 1000; // IST offset in milliseconds (5 hours 30 minutes)
      const currentDateIST = new Date(currentDateUTC.getTime() + ISTOffset); // Convert to IST
      const orderdate = currentDateIST.toISOString();

      const newRecord = new OrderModel({username:req.body.uname,address:req.body.addr,pmode:req.body.pmode,cardetails:req.body.carddetails,orderdt:orderdate,billamt:req.body.tbill,items:req.body.orderitems,status:"Order Received, Processing"});

      const result = await newRecord.save();
      if(result)
      {
        const delresult = await CartModel.deleteMany({username:req.body.uname})
        res.send({code:1})
      }
      else
      {
        res.json({code:0})
      }
    }
    catch(e)
    {
      res.send({code:-1,errmsg:e.message})
      console.log(e);
    }
  })

  app.get("/api/fetchorderdetails", async (req, res) => 
  {
    try 
    {
      const result = await OrderModel.findOne({username:req.query.un}).sort({"orderdt":-1})
      if(result) 
      {
        res.send({ code: 1, orderdet: result });
      } 
      else 
      {
        res.send({ code: 0});
      }
    } 
    catch (e) 
    {
      res.send({ code: -1, errmsg: e.message });
    }
  });

  app.get("/api/searchprods/:text", async (req, res) => 
  {
    try 
    {
      var searchtext=req.params.text;
      const result = await ProdModel.find({prodname: { $regex: '.*' + searchtext ,$options:'i' }})
      if(result.length>0) 
      {
        res.send({ code: 1, productsdata: result });
      } 
      else 
      {
        res.send({ code: 0});
      }
    } 
    catch (e) 
    {
      res.send({ code: -1, errmsg: e.message });
    }
  });

  // app.get("/api/getorders", async (req, res) => 
  // {
  //   try 
  //   {
  //     const result = await OrderModel.find({"orderdt":req.query.odt}).sort({"orderdt":-1})
  //     if (result.length > 0) 
  //     {
  //       res.send({ code: 1, orddata: result });
  //     } 
  //     else 
  //     {
  //       res.send({ code: 0});
  //     }
  //   } 
  //   catch (e) 
  //   {
  //     res.send({ code: -1, errmsg: e.message });
  //   }
  // })

  app.get("/api/getorders", async (req, res) => {
    try {
      const inputDate = req.query.odt; // E.g., "2025-01-20"
  
      // Convert the input date to the start and end of the day
      const startOfDay = new Date(`${inputDate}T00:00:00.000Z`);
      const endOfDay = new Date(`${inputDate}T23:59:59.999Z`);
  
      // Query for records within the date range
      const result = await OrderModel.find({
        orderdt: { $gte: startOfDay, $lte: endOfDay }
      }).sort({ orderdt: -1 });
  
      if (result.length > 0) {
        res.send({ code: 1, orddata: result });
      } else {
        res.send({ code: 0 });
      }
    } catch (e) {
      res.send({ code: -1, errmsg: e.message });
    }
  });

  app.get("/api/getuserorders", async (req, res) => 
    {
      try 
      {
        const result = await OrderModel.find({"username":req.query.un}).sort({"orderdt":-1})
        if (result.length > 0) 
        {
          res.send({ code: 1, orddata: result });
        } 
        else 
        {
          res.send({ code: 0});
        }
      } 
      catch (e) 
      {
        res.send({ code: -1, errmsg: e.message });
      }
    });

  app.get("/api/getorderitems", async (req, res) => 
    {
      try 
      {
        const result = await OrderModel.findOne({"_id":req.query.oid})
        if (result) 
        {
          res.send({ code: 1, itemsdata: result.items});
        } 
        else 
        {
          res.send({ code: 0});
        }
      } 
      catch (e) 
      {
        res.send({ code: -1, errmsg: e.message });
      }
    });

app.put("/api/updatestatus",async(req,res)=>
{
  try
  {
    const result = await OrderModel.updateOne({_id:req.body.ordid},{status:req.body.newstatus})
    console.log(result)
    if(result.modifiedCount===1)
    {
      res.send({code:1})
    }
    else
    {
      res.send({code:0})
    }
  }
  catch(e)
  {
    res.send({code:-1,errmsg:e.message})
  }
})


const CSECRET_KEY = "6LfZidkqAAAAABmkpdGty173iamkdopsmjhuA84g";

app.post("/api/contactus", async (req, res) => 
{
  const { name, phone, email, msg, captchaToken } = req.body;

  if (!captchaToken) 
  {
    return res.status(400).json({ success: false, message: "Captcha token is missing" });
  }

  try {
    // Verify reCAPTCHA with Google
    const response = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        secret: CSECRET_KEY,
        response: captchaToken,
      }),
    });

    const responseData = await response.json(); // Parse the response body

    console.log("Google reCAPTCHA response:", responseData); // Log response data

    if (!responseData.success) {
      return res.status(400).json({ success: false, message: "reCAPTCHA verification failed", details: responseData });
    }

    // Prepare email options
    const mailOptions = {
      from: "class@gtbinstitute.com",
      to: "gtbtrial@gmail.com",
      replyTo: email,
      subject: "Message from Website - Contact Us",
      html: `<b>Name:</b> ${name}<br/><b>Phone:</b> ${phone}<br/><b>Email:</b> ${email}<br/><b>Message:</b> ${msg}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        return res.status(500).json({ success: false, message: "Error sending email" });
      }
      console.log("Email sent: " + info.response);
      res.json({ success: true, message: "Message sent successfully" });
    });

  } catch (error) {
    console.error("Error verifying reCAPTCHA:", error);
    res.status(500).json({ success: false, message: "Error verifying reCAPTCHA", error: error.message });
  }
});





// app.post("/api/contactus",async(req,res)=>
//   {
//     try
//     {
//       const mailOptions = 
//       {
//         from: 'class@gtbinstitute.com',//transporter username email
//         to: 'gtbtrial@gmail.com',//any email id of admin or where you want to receive email
//         replyTo: req.body.email,
//         subject: 'Message from Website - Contact Us',
//         html: `<b>Name:-</b> ${req.body.name}<br/><b>Phone:-</b> ${req.body.phone}<br/><b>Email:-</b> ${req.body.email}
//         <br/><b>Message:-</b> ${req.body.msg}`
//       };
  
//       // Use the transport object to send the email
//       transporter.sendMail(mailOptions, (error, info) => 
//       {
//         if (error) 
//         {
//           console.log(error);
//           res.send('Error sending email');
//         } 
//         else 
//         {
//           console.log('Email sent: ' + info.response);
//           res.send("Message sent successfully");
//         }
//       });
//     }
//     catch(e)
//     {
//       res.send({code:-1,errmsg:e.message})
//     }
//   })

app.listen(port, () => {
  console.log(`Server is running on ${port}`)
})
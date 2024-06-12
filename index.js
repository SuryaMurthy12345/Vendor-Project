var express = require("express");
const dotenv = require("dotenv");

var app = express();
var port = 4000;
const cors = require('cors') 

app.use(cors())
dotenv.config();

var mongoose = require("mongoose");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const multer = require('multer');

mongoose.connect(process.env.mongodb_uri)
    .then(() => console.log("MongoDB Connected Successfully"))
    .catch(err => {
        console.error("MongoDB Connection Error:", err);
        process.exit(1); // Exit the application if the database connection fails
    });


app.use(bodyParser.json());

// Vendor Schema 
const vendorSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    firmids: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'FirmDB',
    }]
});

const Vendor = mongoose.model("VendorDB", vendorSchema);

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.sendStatus(401); // Unauthorized
    }
    const token = authHeader.split(' ')[1];
    if (token == null) {
        return res.sendStatus(401); // Unauthorized
    }
    jwt.verify(token, process.env.secret_key, (err, user) => {
        if (err) {
            console.log(err);
            return res.sendStatus(403); // Forbidden
        }
        req.user = user;
        next();
    });
};

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const vendorEmail = await Vendor.findOne({ email });
        if (vendorEmail) {
            return res.status(400).send("Email already taken");
        }
        const hashedpwd = await bcrypt.hash(password, 10);
        const data = new Vendor({ username, email, password: hashedpwd });
        await data.save();
        res.status(201).json({ message: "Vendor Registered Successfully" });
    } catch (err) {
        res.status(500).json({ err: "Internal Server Error" });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const emailthere = await Vendor.findOne({ email });
        if (!emailthere) {
            return res.status(404).json("Email not found");
        }
        const pwdmatch = await bcrypt.compare(password, emailthere.password);
        if (pwdmatch) {
            const token = jwt.sign({ vendorid: emailthere._id }, process.env.secret_key, { expiresIn: "1h" });
            res.status(200).json({ message: "Login Successful", token });
        } else {
            res.status(401).json("Password not matched");
        }
    } catch (err) {
        res.status(500).json({ err: "Error occurred" });
    }
});

// Firm Schema  
const firmSchema = mongoose.Schema({
    firmname: {
        type: String,
        required: true,
        unique: true
    },
    area: {
        type: String,
        required: true
    },
    category: [{
        type: String,
        enum: ["veg", "non-veg"]
    }],
    region: [{
        type: String,
        enum: ['southindian', 'northindian', 'chinese', 'bakery']
    }],
    offer: {
        type: String
    },
    image: {
        type: String
    },
    vendor: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'VendorDB',
        required: true
    },
    products: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'ProductDB',
        required: true
    }]
});

const Firm = mongoose.model('FirmDB', firmSchema);

app.post('/addFirm', authenticateToken, async (req, res) => {
    const { firmname, area, category, region, offer, image } = req.body;
    const vendor = req.user.vendorid;
    try {
        const newFirm = new Firm({
            firmname,
            area,
            category,
            region,
            offer,
            image,
            vendor
        });

        const saveFirm = await newFirm.save();

        await Vendor.findByIdAndUpdate(vendor, { $push: { firmids: saveFirm._id } });
        res.status(201).json("Firm added successfully");
    } catch (err) {
        console.log(err);
        res.status(500).json({ err: "Internal Server Error" });
    }
});

app.get('/all-Vendors', async (req, res) => {
    try {
        const vendors = await Vendor.find().populate('firmids');
        res.json({ vendors });
    } catch (err) {
        console.error('Error fetching vendors:', err); // Improved error logging
        res.status(500).json({ err: "Internal Server Error" });
    }
});


app.get('/:firmid/products', async (req, res) => {
    try {
        const id = req.params.firmid;
        const restaurant = await Firm.findById(id);
        const firmname = restaurant.firmname;
        const products = await Product.find({ firmid: id });
        res.json({ firmname, products });
    } catch (err) {
        console.log(err);
        res.status(500).json({ err: "Internal Server Error" });
    }
});

const productSchema = mongoose.Schema({
    productname: {
        type: String,
        required: true
    },
    price: {
        type: String,
        required: true
    },
    category: [{
        type: String,
        enum: ["veg", "non-veg"]
    }],
    image: {
        type: String
    },
    bestseller: {
        type: String
    },
    description: {
        type: String
    },
    firmid: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'FirmDB'
    }]
});

const Product = mongoose.model("ProductDB", productSchema);

app.post('/addproduct/:firmid', async (req, res) => {
    const firmid = req.params.firmid;
    const { productname, price, category, image, bestseller, description } = req.body;

    try {
        const newProduct = new Product({
            productname,
            price,
            category,
            image,
            bestseller,
            description,
            firmid
        });
        const saveProduct = await newProduct.save();

        await Firm.findByIdAndUpdate(firmid, { $push: { products: saveProduct._id } });
        res.status(201).json("Product added successfully");
    } catch (err) {
        console.log(err);
        res.status(500).json({ err: "Internal Server Error" });
    }
}); 

app.delete('/deleteproduct/:productid',async(req,res)=>{  
    try{
    const dp = await Product.findByIdAndDelete(req.params.productid) 
    if(!dp){ 
        return res.status(500).json({error:"No product found"})
    }  
} 
catch(err){ 
    console.error(err) 
    res.status(500).json({error:"Internal Server Error"})
}

}) 

app.delete('/deletefirm/:firmid',async(req,res)=>{  
    try{ 

    const firm = await Firm.findById(req.params.firmid) 


    await Product.deleteMany({firmid:firm._id}) 

    await Firm.findByIdAndDelete(req.params.firmid)  

    await Vendor.findByIdAndUpdate(firm.vendor, { $pull: { firmids: firm._id } });

    
    res.status(200).json({ message: "Firm and associated products deleted successfully" });
} 
catch(err){ 
    console.error(err) 
    res.status(500).json({error:"Internal Server Error"})
}

})

app.listen(port, () => {
    console.log("Server Running Successfully at http://localhost:%s", port);
});

app.get('/', (req, res) => {
    res.send("Hello 4000 server baby");
}); 

app.get('/hello', (req, res) => {
    res.send("Hello");
});

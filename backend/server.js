const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();

if (process.env.RENDER) {
  const PING_INTERVAL = 5 * 60 * 1000;
  const pingUrl = process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 5000}`;

  setInterval(async () => {
    try {
      const response = await fetch(`${pingUrl}/api/health`);
      if (response.ok) {
        console.log('✅ Self‑ping successful at', new Date().toISOString());
      } else {
        console.log('⚠️ Self‑ping returned status', response.status);
      }
    } catch (err) {
      console.error('❌ Self‑ping failed:', err.message);
    }
  }, PING_INTERVAL);

  console.log('🔄 Self‑ping system activated (interval: 5 minutes)');
}

app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    environment: process.env.RENDER ? 'render' : 'local'
  });
});

const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : [
      process.env.CLIENT_URL_1,
      process.env.CLIENT_URL_2,
      process.env.FRONTEND_URL,
      process.env.ADMIN_URL,
      'http://localhost:3000',
      'http://localhost:5000',
      'http://localhost:5173',
      'http://127.0.0.1:5500'
    ].filter(Boolean);

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || allowedOrigins.includes('*')) {
      callback(null, true);
    } else {
      console.log('🚫 Blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'amayra',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp', 'gif'],
    transformation: [{ width: 1200, height: 1200, crop: 'limit' }]
  }
});

const upload = multer({ 
  storage, 
  limits: { fileSize: 10 * 1024 * 1024 }
});

const connectWithRetry = () => {
  mongoose.connect(process.env.MONGODB_URI, {
  serverSelectionTimeoutMS: 15000,
  socketTimeoutMS: 45000
}).then(() => {
    console.log('✅ MongoDB Connected');
  }).catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
    console.log('🔄 Retrying connection in 5 seconds...');
    setTimeout(connectWithRetry, 5000);
  });
};

connectWithRetry();

mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB disconnected. Attempting to reconnect...');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconnected');
});

const AdminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, default: 'Admin' },
  role: { type: String, default: 'super_admin' },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

const CategorySchema = new mongoose.Schema({
  name: { type: String, required: true },
  slug: { type: String, required: true, unique: true },
  banglaName: { type: String, required: true },
  description: { type: String },
  imageUrl: { type: String },
  icon: { type: String, default: 'fa-tags' },
  order: { type: Number, default: 0 },
  active: { type: Boolean, default: true }
});

const SliderSchema = new mongoose.Schema({
  title: { type: String, required: true },
  subtitle: { type: String, required: true },
  badge: { type: String, required: true },
  badgeColor: { type: String, default: '#1877F2' },
  imageUrl: { type: String, required: true },
  publicId: { type: String },
  buttonText: { type: String, default: 'এখনই কিনুন' },
  productId: { type: Number },
  order: { type: Number, default: 0 },
  active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const ProductSchema = new mongoose.Schema({
  id: { type: Number, required: true, unique: true },
  name: { type: String, required: true },
  desc: { type: String, required: true },
  original: { type: Number, required: true },
  price: { type: Number, required: true },
  discountPercent: { type: Number, default: 0 },
  category: { type: String, required: true },
  stock: { type: Number, default: 10 },
  sold: { type: Number, default: 0 },
  img: { type: String, required: true },
  images: [{ type: String }],
  publicIds: [{ type: String }],
  featured: { type: Boolean, default: false },
  views: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const OrderSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  customerName: { type: String, required: true },
  phone: { type: String, required: true },
  district: { type: String, required: true },
  address: { type: String, required: true },
  items: [{
    id: Number,
    name: String,
    price: Number,
    quantity: Number
  }],
  subtotal: { type: Number, required: true },
  deliveryCharge: { type: Number, required: true },
  total: { type: Number, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'], 
    default: 'pending' 
  },
  paymentMethod: { type: String, default: 'Cash on Delivery' },
  paymentStatus: { type: String, default: 'pending' },
  notes: { type: String },
  trackingCode: { type: String },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const ReviewSchema = new mongoose.Schema({
  name: { type: String, required: true },
  address: { type: String, required: true },
  text: { type: String, required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  productId: { type: Number },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected'], 
    default: 'pending' 
  },
  isRead: { type: Boolean, default: false },
  isFeatured: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const SettingsSchema = new mongoose.Schema({
  // Basic Settings
  siteName: { type: String, default: 'AMAYRA' },
  siteTitle: { type: String, default: 'AMAYRA · প্রিমিয়াম শার্ট কালেকশন' },
  siteSubtitle: { type: String, default: 'PREMIUM SHIRT COLLECTION' },
  phoneNumber: { type: String, default: '01712345678' },
  whatsappNumber: { type: String, default: '8801712345678' },
  email: { type: String, default: 'info@amayra.com' },
  facebook: { type: String, default: '@amayra.shirt' },
  instagram: { type: String, default: '@amayra' },
  address: { type: String, default: 'Dhaka, Bangladesh' },
  deliveryChargeDhaka: { type: Number, default: 60 },
  deliveryChargeOutside: { type: Number, default: 120 },
  freeDeliveryThreshold: { type: Number, default: 2000 },
  footerText: { type: String, default: 'AMAYRA · প্রিমিয়াম শার্ট কালেকশন · ২০২৫' },
  currency: { type: String, default: '৳' },
  themeColor: { type: String, default: '#1877F2' },
  logo: { type: String },
  
  // SEO Settings
  metaTitle: { type: String, default: 'AMAYRA · প্রিমিয়াম শার্ট কালেকশন' },
  metaDescription: { type: String, default: 'প্রিমিয়াম কোয়ালিটির ফরমাল, ক্যাজুয়াল ও প্রিমিয়াম শার্ট সেরা দামে। AMAYRA তে অর্ডার করুন দ্রুত ডেলিভারি পাবেন।' },
  metaKeywords: { type: String, default: 'শার্ট, ফরমাল শার্ট, ক্যাজুয়াল শার্ট, প্রিমিয়াম শার্ট, পাঞ্জাবি, ঢাকা, বাংলাদেশ, AMAYRA' },
  metaAuthor: { type: String, default: 'AMAYRA' },
  ogTitle: { type: String, default: 'AMAYRA · প্রিমিয়াম শার্ট কালেকশন' },
  ogDescription: { type: String, default: 'প্রিমিয়াম কোয়ালিটির ফরমাল, ক্যাজুয়াল ও প্রিমিয়াম শার্ট সেরা দামে।' },
  ogImage: { type: String, default: 'images/Amayra.jpg' },
  googleSiteVerification: { type: String, default: 'SFq3YDKWo-0iRrNXCwYND3ygW9ThJJUQaK1zTMiqf44' },
  
  updatedAt: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', AdminSchema);
const Category = mongoose.model('Category', CategorySchema);
const Slider = mongoose.model('Slider', SliderSchema);
const Product = mongoose.model('Product', ProductSchema);
const Order = mongoose.model('Order', OrderSchema);
const Review = mongoose.model('Review', ReviewSchema);
const Settings = mongoose.model('Settings', SettingsSchema);

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error();
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.id);
    if (!admin) throw new Error();
    req.admin = admin;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Please authenticate' });
  }
};

async function initializeDatabase() {
  try {
    const adminExists = await Admin.findOne({ username: process.env.ADMIN_USERNAME });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
      await Admin.create({ 
        username: process.env.ADMIN_USERNAME, 
        password: hashedPassword,
        name: 'Super Admin'
      });
      console.log('✅ Default admin created');
    }

    const settingsExists = await Settings.findOne();
    if (!settingsExists) {
      await Settings.create({});
      console.log('✅ Default settings created');
    }

    const categoriesExist = await Category.countDocuments();
    if (categoriesExist === 0) {
      const defaultCategories = [
        { name: 'formal', slug: 'formal', banglaName: 'ফরমাল', order: 1, icon: 'fa-user-tie' },
        { name: 'casual', slug: 'casual', banglaName: 'ক্যাজুয়াল', order: 2, icon: 'fa-shirt' },
        { name: 'premium', slug: 'premium', banglaName: 'প্রিমিয়াম', order: 3, icon: 'fa-crown' }
      ];
      await Category.insertMany(defaultCategories);
      console.log('✅ Default categories created');
    }

    const slidersExist = await Slider.countDocuments();
    if (slidersExist === 0) {
      const defaultSliders = [
        { 
          title: 'প্রিমিয়াম কালেকশন', 
          subtitle: 'আড়ম্বরপূর্ণ ডিজাইন, অনন্য গুণগত মান', 
          badge: 'সীমিত অফার', 
          badgeColor: '#1877F2', 
          imageUrl: 'https://images.unsplash.com/photo-1598033128083-2f68a5d9b1b1?w=1200&q=85', 
          productId: 1, 
          order: 1 
        },
        { 
          title: 'হোয়াইট প্রিমিয়াম', 
          subtitle: 'হাতের ছোঁয়ায় প্রিমিয়াম সুতি', 
          badge: 'বেস্টসেলার', 
          badgeColor: '#FF7A00', 
          imageUrl: 'https://images.unsplash.com/photo-1602810316693-3667c854239a?w=1200&q=85', 
          productId: 2, 
          order: 2 
        },
        { 
          title: 'ডেনিম প্যাচ', 
          subtitle: 'হাতের কাজ করা লিমিটেড এডিশন', 
          badge: 'এক্সক্লুসিভ', 
          badgeColor: '#1877F2', 
          imageUrl: 'https://images.unsplash.com/photo-1588359348347-9bc6cbbb689c?w=1200&q=85', 
          productId: 5, 
          order: 3 
        }
      ];
      await Slider.insertMany(defaultSliders);
      console.log('✅ Default sliders created');
    }
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

app.post('/api/admin/login', [
  body('username').notEmpty(),
  body('password').notEmpty()
], validate, async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username });
    
    if (!admin) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    admin.lastLogin = new Date();
    await admin.save();

    const token = jwt.sign(
      { id: admin._id, username: admin.username, name: admin.name },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ 
      token, 
      admin: { 
        username: admin.username, 
        name: admin.name,
        id: admin._id 
      } 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/verify', auth, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin._id).select('-password');
    res.json(admin);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const admin = await Admin.findById(req.admin._id);
    
    const isMatch = await bcrypt.compare(currentPassword, admin.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    admin.password = await bcrypt.hash(newPassword, 10);
    await admin.save();
    
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Public Routes
app.get('/api/categories', async (req, res) => {
  try {
    const categories = await Category.find({ active: true }).sort('order');
    res.json(categories);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/sliders', async (req, res) => {
  try {
    const sliders = await Slider.find({ active: true }).sort('order');
    res.json(sliders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/products', async (req, res) => {
  try {
    const { category, search, featured, sort, limit } = req.query;
    let filter = {};
    let sortOptions = {};
    
    if (category && category !== 'all') filter.category = category;
    if (featured === 'true') filter.featured = true;
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { desc: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (sort === 'sold') {
      sortOptions = { sold: -1 };
    } else {
      sortOptions = { id: 1 };
    }

    let query = Product.find(filter).sort(sortOptions);
    
    if (limit) {
      query = query.limit(parseInt(limit));
    }

    const products = await query;
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findOne({ id: parseInt(req.params.id) });
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    product.views += 1;
    await product.save();
    
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/orders', [
  body('customerName').notEmpty(),
  body('phone').matches(/^01[3-9]\d{8}$/),
  body('address').notEmpty(),
  body('items').isArray().notEmpty()
], validate, async (req, res) => {
  try {
    const { customerName, phone, district, address, items, subtotal, deliveryCharge, total, notes } = req.body;
    
    const orderId = 'ORD' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).substring(2, 5).toUpperCase();
    
    const order = new Order({ 
      orderId, 
      customerName, 
      phone, 
      district, 
      address, 
      items, 
      subtotal, 
      deliveryCharge, 
      total, 
      notes 
    });
    
    await order.save();

    for (const item of items) {
      await Product.findOneAndUpdate(
        { id: item.id }, 
        { $inc: { sold: item.quantity, stock: -item.quantity } }
      );
    }

    res.status(201).json({ orderId, message: 'Order placed successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/reviews', async (req, res) => {
  try {
    const { featured } = req.query;
    let filter = { status: 'approved' };
    if (featured === 'true') filter.isFeatured = true;
    
    const reviews = await Review.find(filter)
      .sort('-createdAt')
      .limit(20);
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/reviews', [
  body('name').notEmpty(),
  body('address').notEmpty(),
  body('text').notEmpty(),
  body('rating').isInt({ min: 1, max: 5 })
], validate, async (req, res) => {
  try {
    const { name, address, text, rating, productId } = req.body;
    const review = new Review({ name, address, text, rating, productId });
    await review.save();
    res.status(201).json({ message: 'Review submitted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/settings', async (req, res) => {
  try {
    let settings = await Settings.findOne();
    if (!settings) {
      settings = await Settings.create({});
    }
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin Routes
app.get('/api/admin/categories', auth, async (req, res) => {
  try {
    const categories = await Category.find().sort('order');
    res.json(categories);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/categories', auth, async (req, res) => {
  try {
    const { name, banglaName, description, order, active, icon } = req.body;
    const slug = name.toLowerCase().replace(/\s+/g, '-');
    
    const existing = await Category.findOne({ slug });
    if (existing) {
      return res.status(400).json({ error: 'Category slug already exists' });
    }

    const category = new Category({ 
      name, 
      slug, 
      banglaName, 
      description, 
      icon: icon || 'fa-tags',
      order: order || 0, 
      active: active !== false 
    });
    
    await category.save();
    res.status(201).json(category);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/categories/:id', auth, async (req, res) => {
  try {
    const { name, banglaName, description, order, active, icon } = req.body;
    const slug = name.toLowerCase().replace(/\s+/g, '-');
    
    const category = await Category.findByIdAndUpdate(
      req.params.id, 
      { name, slug, banglaName, description, icon, order, active }, 
      { new: true }
    );
    
    res.json(category);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/categories/:id', auth, async (req, res) => {
  try {
    const products = await Product.findOne({ category: req.params.id });
    if (products) {
      return res.status(400).json({ error: 'Cannot delete category with products' });
    }
    
    await Category.findByIdAndDelete(req.params.id);
    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/sliders', auth, async (req, res) => {
  try {
    const sliders = await Slider.find().sort('order');
    res.json(sliders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/sliders', auth, upload.single('image'), async (req, res) => {
  try {
    const sliderData = JSON.parse(req.body.data || '{}');
    
    if (sliderData.productId) {
      const product = await Product.findOne({ id: sliderData.productId });
      if (!product) {
        return res.status(400).json({ error: 'Invalid product ID' });
      }
    }
    
    if (!req.file) {
      return res.status(400).json({ error: 'Image is required' });
    }
    
    const newSlider = new Slider({
      title: sliderData.title,
      subtitle: sliderData.subtitle,
      badge: sliderData.badge,
      badgeColor: sliderData.badgeColor,
      buttonText: sliderData.buttonText,
      productId: sliderData.productId,
      order: sliderData.order || 0,
      active: sliderData.active === true || sliderData.active === 'true',
      imageUrl: req.file.path,
      publicId: req.file.filename
    });

    await newSlider.save();
    res.status(201).json(newSlider);
  } catch (error) {
    console.error('Error creating slider:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/sliders/:id', auth, upload.single('image'), async (req, res) => {
  try {
    const sliderData = JSON.parse(req.body.data || '{}');
    
    if (sliderData.productId) {
      const product = await Product.findOne({ id: sliderData.productId });
      if (!product) {
        return res.status(400).json({ error: 'Invalid product ID' });
      }
    }
    
    const updateData = {
      title: sliderData.title,
      subtitle: sliderData.subtitle,
      badge: sliderData.badge,
      badgeColor: sliderData.badgeColor,
      buttonText: sliderData.buttonText,
      productId: sliderData.productId,
      order: sliderData.order || 0,
      active: sliderData.active === true || sliderData.active === 'true'
    };

    if (req.file) {
      updateData.imageUrl = req.file.path;
      updateData.publicId = req.file.filename;
      
      const oldSlider = await Slider.findById(req.params.id);
      if (oldSlider?.publicId) {
        await cloudinary.uploader.destroy(oldSlider.publicId);
      }
    }

    const slider = await Slider.findByIdAndUpdate(req.params.id, updateData, { new: true });
    res.json(slider);
  } catch (error) {
    console.error('Error updating slider:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/sliders/:id', auth, async (req, res) => {
  try {
    const slider = await Slider.findById(req.params.id);
    if (slider?.publicId) {
      await cloudinary.uploader.destroy(slider.publicId);
    }
    await Slider.findByIdAndDelete(req.params.id);
    res.json({ message: 'Slider deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/products', auth, async (req, res) => {
  try {
    const products = await Product.find().sort('id');
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/bestsellers', auth, async (req, res) => {
  try {
    const bestsellers = await Product.find()
      .sort({ sold: -1 })
      .limit(5)
      .select('id name desc original price images sold discountPercent stock');
    
    res.json(bestsellers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/products/temp-upload', auth, upload.array('images', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No images uploaded' });
    }

    const urls = req.files.map(f => f.path);
    res.json({ urls });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/products', auth, upload.array('images', 10), async (req, res) => {
  try {
    const productData = JSON.parse(req.body.data || '{}');
    
    const lastProduct = await Product.findOne().sort('-id');
    const nextId = lastProduct ? lastProduct.id + 1 : 13;

    const imageUrls = req.files && req.files.length > 0 
      ? req.files.map(f => f.path) 
      : (productData.images && productData.images.length > 0 ? productData.images : []);
    
    const publicIds = req.files && req.files.length > 0 
      ? req.files.map(f => f.filename) 
      : [];

    if (imageUrls.length === 0) {
      return res.status(400).json({ error: 'At least one image is required' });
    }

    const product = new Product({
      id: nextId,
      name: productData.name,
      desc: productData.desc,
      original: productData.original,
      price: productData.price,
      discountPercent: productData.discountPercent || Math.round(((productData.original - productData.price) / productData.original) * 100),
      category: productData.category,
      stock: productData.stock || 10,
      sold: productData.sold || 0,
      img: imageUrls[0],
      images: imageUrls,
      publicIds,
      featured: productData.featured || false
    });

    await product.save();
    res.status(201).json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/products/:id', auth, upload.array('images', 10), async (req, res) => {
  try {
    const productData = JSON.parse(req.body.data || '{}');
    const product = await Product.findById(req.params.id);
    
    let imageUrls = product.images;
    let publicIds = product.publicIds;

    if (req.files && req.files.length > 0) {
      if (product.publicIds && product.publicIds.length > 0) {
        for (const publicId of product.publicIds) {
          await cloudinary.uploader.destroy(publicId);
        }
      }
      
      imageUrls = req.files.map(f => f.path);
      publicIds = req.files.map(f => f.filename);
    } else if (productData.images && productData.images.length > 0) {
      imageUrls = productData.images;
    }

    const updatedProduct = await Product.findByIdAndUpdate(
      req.params.id,
      {
        name: productData.name,
        desc: productData.desc,
        original: productData.original,
        price: productData.price,
        discountPercent: productData.discountPercent || Math.round(((productData.original - productData.price) / productData.original) * 100),
        category: productData.category,
        stock: productData.stock,
        sold: productData.sold,
        img: imageUrls[0],
        images: imageUrls,
        publicIds,
        featured: productData.featured,
        updatedAt: Date.now()
      },
      { new: true }
    );

    res.json(updatedProduct);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/products/:id', auth, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    
    if (product?.publicIds && product.publicIds.length > 0) {
      for (const publicId of product.publicIds) {
        await cloudinary.uploader.destroy(publicId);
      }
    }
    
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/orders', auth, async (req, res) => {
  try {
    const { status, page = 1, limit = 20, search, isRead } = req.query;
    const query = {};
    
    if (status && status !== 'all') query.status = status;
    if (isRead !== undefined) query.isRead = isRead === 'true';
    if (search) {
      query.$or = [
        { orderId: { $regex: search, $options: 'i' } },
        { customerName: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } }
      ];
    }

    const orders = await Order.find(query)
      .sort('-createdAt')
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Order.countDocuments(query);

    res.json({ 
      orders, 
      totalPages: Math.ceil(total / limit), 
      currentPage: parseInt(page), 
      total 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/orders/unread-count', auth, async (req, res) => {
  try {
    const count = await Order.countDocuments({ isRead: false });
    res.json({ count });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/orders/:id', auth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    await Order.findByIdAndUpdate(req.params.id, { isRead: true });
    res.json(order);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/orders/:id', auth, async (req, res) => {
  try {
    const { status, paymentStatus, notes, trackingCode } = req.body;
    const order = await Order.findByIdAndUpdate(
      req.params.id, 
      { status, paymentStatus, notes, trackingCode, updatedAt: Date.now() }, 
      { new: true }
    );
    res.json(order);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/orders/:id/read', auth, async (req, res) => {
  try {
    await Order.findByIdAndUpdate(req.params.id, { isRead: true });
    res.json({ message: 'Order marked as read' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/orders/:id', auth, async (req, res) => {
  try {
    await Order.findByIdAndDelete(req.params.id);
    res.json({ message: 'Order deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/reviews', auth, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const query = {};
    if (status && status !== 'all') query.status = status;

    const reviews = await Review.find(query)
      .sort('-createdAt')
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Review.countDocuments(query);

    res.json({ 
      reviews, 
      totalPages: Math.ceil(total / limit), 
      currentPage: parseInt(page), 
      total 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/reviews/unread-count', auth, async (req, res) => {
  try {
    const count = await Review.countDocuments({ isRead: false });
    res.json({ count });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/reviews/:id', auth, async (req, res) => {
  try {
    const review = await Review.findById(req.params.id);
    if (!review) {
      return res.status(404).json({ error: 'Review not found' });
    }
    
    await Review.findByIdAndUpdate(req.params.id, { isRead: true });
    res.json(review);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/reviews/:id', auth, async (req, res) => {
  try {
    const { status, isFeatured } = req.body;
    const review = await Review.findByIdAndUpdate(
      req.params.id, 
      { status, isFeatured, isRead: true }, 
      { new: true }
    );
    res.json(review);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/reviews/:id', auth, async (req, res) => {
  try {
    await Review.findByIdAndDelete(req.params.id);
    res.json({ message: 'Review deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/settings', auth, async (req, res) => {
  try {
    let settings = await Settings.findOne();
    if (!settings) {
      settings = await Settings.create({});
    }
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/settings', auth, async (req, res) => {
  try {
    const settings = await Settings.findOneAndUpdate(
      {}, 
      { ...req.body, updatedAt: Date.now() }, 
      { new: true, upsert: true }
    );
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/dashboard', auth, async (req, res) => {
  try {
    const totalOrders = await Order.countDocuments();
    const pendingOrders = await Order.countDocuments({ status: 'pending' });
    const confirmedOrders = await Order.countDocuments({ status: 'confirmed' });
    const processingOrders = await Order.countDocuments({ status: 'processing' });
    const shippedOrders = await Order.countDocuments({ status: 'shipped' });
    const deliveredOrders = await Order.countDocuments({ status: 'delivered' });
    const cancelledOrders = await Order.countDocuments({ status: 'cancelled' });
    const totalProducts = await Product.countDocuments();
    const totalReviews = await Review.countDocuments();
    const pendingReviews = await Review.countDocuments({ status: 'pending' });
    
    const recentOrders = await Order.find()
      .sort('-createdAt')
      .limit(5);
    
    const revenue = await Order.aggregate([
      { $match: { status: { $in: ['delivered', 'shipped'] } } },
      { $group: { _id: null, total: { $sum: '$total' } } }
    ]);

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayOrders = await Order.countDocuments({ createdAt: { $gte: today } });

    const lowStock = await Product.countDocuments({ stock: { $lt: 5 } });

    res.json({
      stats: { 
        totalOrders, 
        pendingOrders,
        confirmedOrders,
        processingOrders,
        shippedOrders,
        deliveredOrders,
        cancelledOrders,
        totalProducts, 
        totalReviews, 
        pendingReviews, 
        revenue: revenue[0]?.total || 0,
        todayOrders,
        lowStock
      },
      recentOrders
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/chart-data', auth, async (req, res) => {
  try {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const orders = await Order.aggregate([
      { $match: { createdAt: { $gte: sevenDaysAgo } } },
      { $group: { 
        _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }, 
        count: { $sum: 1 } 
      }},
      { $sort: { _id: 1 } }
    ]);

    const labels = [];
    const data = [];

    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().split('T')[0];
      labels.push(dateStr);
      
      const found = orders.find(o => o._id === dateStr);
      data.push(found ? found.count : 0);
    }

    res.json({ labels, data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/notifications/unread', auth, async (req, res) => {
  try {
    const [pendingOrders, pendingReviews] = await Promise.all([
      Order.countDocuments({ status: 'pending', isRead: false }),
      Review.countDocuments({ status: 'pending', isRead: false })
    ]);

    const notifications = [];

    if (pendingOrders > 0) {
      const recentOrders = await Order.find({ status: 'pending', isRead: false })
        .sort({ createdAt: -1 })
        .limit(5)
        .select('orderId customerName createdAt');

      notifications.push({
        type: 'order',
        count: pendingOrders,
        items: recentOrders
      });
    }

    if (pendingReviews > 0) {
      const recentReviews = await Review.find({ status: 'pending', isRead: false })
        .sort({ createdAt: -1 })
        .limit(5)
        .select('name text createdAt');

      notifications.push({
        type: 'review',
        count: pendingReviews,
        items: recentReviews
      });
    }

    res.json({
      total: pendingOrders + pendingReviews,
      notifications
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

initializeDatabase().then(() => {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`✅ Allowed origins:`, allowedOrigins);
  });
});
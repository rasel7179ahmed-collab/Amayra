const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

dotenv.config();

const app = express();

// ========== Render Self‑Ping (স্লিপ প্রতিরোধ) ==========
// শুধুমাত্র Render পরিবেশে চললে প্রতি ৫ মিনিটে নিজেকে কল করবে
if (process.env.RENDER) {
  const PING_INTERVAL = 5 * 60 * 1000; // ৫ মিনিট
  const port = process.env.PORT || 5000;
  // প্রথমে লোকালহোস্ট দিয়ে চেষ্টা করবে, পরে পাবলিক URL দিয়ে
  const pingUrl = process.env.RENDER_EXTERNAL_URL || `http://localhost:${port}`;

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

// ========== হেল্থ চেক এন্ডপয়েন্ট ==========
// এই এন্ডপয়েন্টটি সেলফ-পিং এবং UptimeRobot-এর জন্যও ব্যবহার করা যাবে
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    environment: process.env.RENDER ? 'render' : 'local'
  });
});

// ========== CORS কনফিগারেশন ==========
const allowedOrigins = [
  process.env.CLIENT_URL_1,
  process.env.CLIENT_URL_2,
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5500'
].filter(Boolean);

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false
}));
app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  optionsSuccessStatus: 200
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ========== রেট লিমিটিং ==========
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// ========== Cloudinary কনফিগার ==========
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// ========== মুল্টার স্টোরেজ ==========
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'amayra/products',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 800, height: 1000, crop: 'limit' }]
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// ========== MongoDB সংযোগ ==========
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000
}).then(() => {
  console.log('✅ MongoDB Connected');
}).catch(err => {
  console.error('❌ MongoDB Connection Error:', err);
  process.exit(1);
});

// ========== SCHEMAS ==========
const AdminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
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

const CategorySchema = new mongoose.Schema({
  name: { type: String, required: true },
  slug: { type: String, required: true, unique: true },
  banglaName: { type: String, required: true },
  description: { type: String },
  imageUrl: { type: String },
  order: { type: Number, default: 0 },
  active: { type: Boolean, default: true }
});

const ProductSchema = new mongoose.Schema({
  id: { type: Number, required: true, unique: true },
  name: { type: String, required: true },
  desc: { type: String, required: true },
  original: { type: Number, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  stock: { type: Number, default: 10 },
  sold: { type: Number, default: 0 },
  img: { type: String, required: true },
  images: [{ type: String }],
  publicIds: [{ type: String }],
  featured: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
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
  status: { type: String, enum: ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'], default: 'pending' },
  paymentMethod: { type: String, default: 'Cash on Delivery' },
  paymentStatus: { type: String, default: 'pending' },
  notes: { type: String },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const ReviewSchema = new mongoose.Schema({
  name: { type: String, required: true },
  address: { type: String, required: true },
  text: { type: String, required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const SettingsSchema = new mongoose.Schema({
  siteName: { type: String, default: 'AMAYRA' },
  siteTitle: { type: String, default: 'AMAYRA · প্রিমিয়াম শার্ট কালেকশন' },
  phoneNumber: { type: String, default: '01712345678' },
  whatsappNumber: { type: String, default: '8801712345678' },
  email: { type: String, default: 'info@amayra.com' },
  facebook: { type: String, default: '@amayra.shirt' },
  address: { type: String, default: 'Dhaka, Bangladesh' },
  deliveryChargeDhaka: { type: Number, default: 60 },
  deliveryChargeOutside: { type: Number, default: 120 },
  freeDeliveryThreshold: { type: Number, default: 2000 },
  footerText: { type: String, default: 'AMAYRA · প্রিমিয়াম শার্ট কালেকশন · ২০২৫' },
  updatedAt: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', AdminSchema);
const Slider = mongoose.model('Slider', SliderSchema);
const Category = mongoose.model('Category', CategorySchema);
const Product = mongoose.model('Product', ProductSchema);
const Order = mongoose.model('Order', OrderSchema);
const Review = mongoose.model('Review', ReviewSchema);
const Settings = mongoose.model('Settings', SettingsSchema);

// ========== MIDDLEWARE ==========
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

// ========== INITIAL SETUP ==========
async function initializeDatabase() {
  try {
    const adminExists = await Admin.findOne({ username: process.env.ADMIN_USERNAME });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
      await Admin.create({ username: process.env.ADMIN_USERNAME, password: hashedPassword });
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
        { name: 'formal', slug: 'formal', banglaName: 'ফরমাল', order: 1 },
        { name: 'casual', slug: 'casual', banglaName: 'ক্যাজুয়াল', order: 2 },
        { name: 'premium', slug: 'premium', banglaName: 'প্রিমিয়াম', order: 3 }
      ];
      await Category.insertMany(defaultCategories);
      console.log('✅ Default categories created');
    }
    const slidersExist = await Slider.countDocuments();
    if (slidersExist === 0) {
      const defaultSliders = [
        { title: 'প্রিমিয়াম কালেকশন', subtitle: 'আড়ম্বরপূর্ণ ডিজাইন, অনন্য গুণগত মান', badge: 'সীমিত অফার', badgeColor: '#1877F2', imageUrl: 'https://images.unsplash.com/photo-1598033128083-2f68a5d9b1b1?w=1200&q=85', productId: 1, order: 1 },
        { title: 'হোয়াইট প্রিমিয়াম', subtitle: 'হাতের ছোঁয়ায় প্রিমিয়াম সুতি', badge: 'বেস্টসেলার', badgeColor: '#FF7A00', imageUrl: 'https://images.unsplash.com/photo-1602810316693-3667c854239a?w=1200&q=85', productId: 2, order: 2 },
        { title: 'ডেনিম প্যাচ', subtitle: 'হাতের কাজ করা লিমিটেড এডিশন', badge: 'এক্সক্লুসিভ', badgeColor: '#1877F2', imageUrl: 'https://images.unsplash.com/photo-1588359348347-9bc6cbbb689c?w=1200&q=85', productId: 5, order: 3 }
      ];
      await Slider.insertMany(defaultSliders);
      console.log('✅ Default sliders created');
    }
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// ========== API ROUTES ==========
// (এখানে আপনার সব API রুট অপরিবর্তিত থাকবে)

// Auth
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username });
    if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, admin: { username: admin.username, id: admin._id } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const admin = await Admin.findById(req.admin._id);
    const isMatch = await bcrypt.compare(currentPassword, admin.password);
    if (!isMatch) return res.status(400).json({ error: 'Current password is incorrect' });
    admin.password = await bcrypt.hash(newPassword, 10);
    await admin.save();
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Sliders
app.get('/api/sliders', async (req, res) => {
  try {
    const sliders = await Slider.find({ active: true }).sort('order');
    res.json(sliders);
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
    const newSlider = new Slider({
      title: sliderData.title,
      subtitle: sliderData.subtitle,
      badge: sliderData.badge,
      badgeColor: sliderData.badgeColor,
      buttonText: sliderData.buttonText,
      productId: sliderData.productId,
      order: sliderData.order,
      active: sliderData.active === 'true' || sliderData.active === true,
      imageUrl: req.file ? req.file.path : sliderData.imageUrl,
      publicId: req.file ? req.file.filename : null
    });
    await newSlider.save();
    res.status(201).json(newSlider);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/sliders/:id', auth, upload.single('image'), async (req, res) => {
  try {
    const sliderData = JSON.parse(req.body.data || '{}');
    const updateData = {
      title: sliderData.title,
      subtitle: sliderData.subtitle,
      badge: sliderData.badge,
      badgeColor: sliderData.badgeColor,
      buttonText: sliderData.buttonText,
      productId: sliderData.productId,
      order: sliderData.order,
      active: sliderData.active === 'true' || sliderData.active === true
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
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/sliders/:id', auth, async (req, res) => {
  try {
    const slider = await Slider.findById(req.params.id);
    if (slider?.publicId) await cloudinary.uploader.destroy(slider.publicId);
    await Slider.findByIdAndDelete(req.params.id);
    res.json({ message: 'Slider deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Categories
app.get('/api/categories', async (req, res) => {
  try {
    const categories = await Category.find({ active: true }).sort('order');
    res.json(categories);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

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
    const { name, banglaName, description, order, active } = req.body;
    const slug = name.toLowerCase().replace(/\s+/g, '-');
    const category = new Category({ name, slug, banglaName, description, order, active });
    await category.save();
    res.status(201).json(category);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/categories/:id', auth, async (req, res) => {
  try {
    const { name, banglaName, description, order, active } = req.body;
    const slug = name.toLowerCase().replace(/\s+/g, '-');
    const category = await Category.findByIdAndUpdate(req.params.id, { name, slug, banglaName, description, order, active }, { new: true });
    res.json(category);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/categories/:id', auth, async (req, res) => {
  try {
    await Category.findByIdAndDelete(req.params.id);
    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find().sort('id');
    res.json(products);
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

app.post('/api/admin/products', auth, upload.array('images', 10), async (req, res) => {
  try {
    const productData = JSON.parse(req.body.data || '{}');
    const lastProduct = await Product.findOne().sort('-id');
    const nextId = lastProduct ? lastProduct.id + 1 : 13;
    const imageUrls = req.files ? req.files.map(f => f.path) : [];
    const publicIds = req.files ? req.files.map(f => f.filename) : [];
    const product = new Product({
      id: nextId,
      name: productData.name,
      desc: productData.desc,
      original: productData.original,
      price: productData.price,
      category: productData.category,
      stock: productData.stock,
      sold: productData.sold || 0,
      img: imageUrls[0] || productData.img,
      images: imageUrls.length ? imageUrls : [productData.img],
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
    }
    const updatedProduct = await Product.findByIdAndUpdate(req.params.id, {
      name: productData.name,
      desc: productData.desc,
      original: productData.original,
      price: productData.price,
      category: productData.category,
      stock: productData.stock,
      sold: productData.sold,
      img: imageUrls[0],
      images: imageUrls,
      publicIds,
      featured: productData.featured
    }, { new: true });
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

// Orders
app.post('/api/orders', async (req, res) => {
  try {
    const { customerName, phone, district, address, items, subtotal, deliveryCharge, total, notes } = req.body;
    const orderId = 'ORD' + Date.now() + Math.floor(Math.random() * 1000);
    const order = new Order({ orderId, customerName, phone, district, address, items, subtotal, deliveryCharge, total, notes });
    await order.save();
    for (const item of items) {
      await Product.findOneAndUpdate({ id: item.id }, { $inc: { sold: item.quantity, stock: -item.quantity } });
    }
    res.status(201).json({ orderId, message: 'Order placed successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/orders', auth, async (req, res) => {
  try {
    const { status, page = 1, limit = 20, isRead } = req.query;
    const query = {};
    if (status) query.status = status;
    if (isRead !== undefined) query.isRead = isRead === 'true';
    const orders = await Order.find(query).sort('-createdAt').limit(limit * 1).skip((page - 1) * limit);
    const total = await Order.countDocuments(query);
    res.json({ orders, totalPages: Math.ceil(total / limit), currentPage: page, total });
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

app.put('/api/admin/orders/:id', auth, async (req, res) => {
  try {
    const { status, paymentStatus, notes } = req.body;
    const order = await Order.findByIdAndUpdate(req.params.id, { status, paymentStatus, notes }, { new: true });
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

// Reviews
app.get('/api/reviews', async (req, res) => {
  try {
    const reviews = await Review.find({ status: 'approved' }).sort('-createdAt').limit(20);
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/reviews', async (req, res) => {
  try {
    const { name, address, text, rating } = req.body;
    const review = new Review({ name, address, text, rating });
    await review.save();
    res.status(201).json({ message: 'Review submitted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/reviews', auth, async (req, res) => {
  try {
    const { status } = req.query;
    const query = {};
    if (status) query.status = status;
    const reviews = await Review.find(query).sort('-createdAt');
    res.json(reviews);
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

app.put('/api/admin/reviews/:id', auth, async (req, res) => {
  try {
    const { status } = req.body;
    const review = await Review.findByIdAndUpdate(req.params.id, { status, isRead: true }, { new: true });
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

// Settings
app.get('/api/settings', async (req, res) => {
  try {
    const settings = await Settings.findOne();
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/settings', auth, async (req, res) => {
  try {
    const settings = await Settings.findOne();
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/settings', auth, async (req, res) => {
  try {
    const settings = await Settings.findOneAndUpdate({}, { ...req.body, updatedAt: Date.now() }, { new: true, upsert: true });
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Dashboard stats
app.get('/api/admin/dashboard', auth, async (req, res) => {
  try {
    const totalOrders = await Order.countDocuments();
    const pendingOrders = await Order.countDocuments({ status: 'pending' });
    const totalProducts = await Product.countDocuments();
    const totalReviews = await Review.countDocuments();
    const pendingReviews = await Review.countDocuments({ status: 'pending' });
    const recentOrders = await Order.find().sort('-createdAt').limit(5);
    const revenue = await Order.aggregate([
      { $match: { status: { $in: ['delivered', 'shipped'] } } },
      { $group: { _id: null, total: { $sum: '$total' } } }
    ]);
    res.json({
      stats: { totalOrders, pendingOrders, totalProducts, totalReviews, pendingReviews, revenue: revenue[0]?.total || 0 },
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
      { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]);
    const labels = [], data = [];
    for (let i = 0; i < 7; i++) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().split('T')[0];
      labels.unshift(dateStr);
      const found = orders.find(o => o._id === dateStr);
      data.unshift(found ? found.count : 0);
    }
    res.json({ labels, data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== ইনিশিয়ালাইজ ও সার্ভার চালু ==========
initializeDatabase().then(() => {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`✅ Allowed origins:`, allowedOrigins);
  });
});
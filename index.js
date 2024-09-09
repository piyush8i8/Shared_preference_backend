// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt'); // For password hashing
const cors = require('cors');

// Initialize Express
const app = express();

// Middleware
app.use(cors());
app.use(express.json()); // For parsing application/json
app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/Sem5', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('Failed to connect to MongoDB', err));

// Define a schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    status: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
});

// Create a model
const User = mongoose.model('User', userSchema);

// API route to handle signup
app.post('/api/signup', async (req, res) => {
    const { name, email, phone, password } = req.body;

    try {
        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            name,
            email,
            phone,
            password: hashedPassword, // Store the hashed password
        });

        await newUser.save();
        res.status(201).json({ message: 'User created successfully', userId: newUser._id });
    } catch (error) {
        if (error.code === 11000) { // Duplicate key error
            res.status(400).json({ error: 'Email already in use' });
        } else {
            res.status(400).json({ error: 'Error creating user', details: error });
        }
    }
});

// API route to handle signin
app.post('/api/signin', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Compare the hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Incorrect password' });
        }

        res.status(200).json({ message: 'User signed in successfully', userId: user._id });
    } catch (error) {
        res.status(400).json({ error: 'Error signing in', details: error });
    }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

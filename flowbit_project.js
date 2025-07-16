// Project Structure and Complete Implementation

// ========================================
// docker-compose.yml
// ========================================
version: '3.8'

services:
  mongodb:
    image: mongo:5.0
    container_name: flowbit-mongodb
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: password
    volumes:
      - mongodb_data:/data/db
    networks:
      - flowbit-network

  n8n:
    image: docker.n8n.io/n8nio/n8n:latest
    container_name: flowbit-n8n
    ports:
      - "5678:5678"
    environment:
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=admin
      - N8N_BASIC_AUTH_PASSWORD=password
      - WEBHOOK_URL=http://host.docker.internal:3001
    volumes:
      - n8n_data:/home/node/.n8n
    networks:
      - flowbit-network

  api-gateway:
    build: ./packages/api-gateway
    container_name: flowbit-api
    ports:
      - "3001:3001"
    environment:
      - MONGODB_URI=mongodb://admin:password@mongodb:27017/flowbit?authSource=admin
      - JWT_SECRET=your-super-secret-jwt-key
      - N8N_WEBHOOK_SECRET=shared-secret-123
      - N8N_URL=http://n8n:5678
    depends_on:
      - mongodb
      - n8n
    networks:
      - flowbit-network

  react-shell:
    build: ./packages/react-shell
    container_name: flowbit-shell
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://localhost:3001
    depends_on:
      - api-gateway
    networks:
      - flowbit-network

  support-tickets-app:
    build: ./packages/support-tickets-app
    container_name: flowbit-tickets
    ports:
      - "3002:3002"
    environment:
      - REACT_APP_API_URL=http://localhost:3001
    depends_on:
      - api-gateway
    networks:
      - flowbit-network

  ngrok:
    image: ngrok/ngrok:latest
    container_name: flowbit-ngrok
    command: http api-gateway:3001
    environment:
      - NGROK_AUTHTOKEN=${NGROK_AUTHTOKEN}
    depends_on:
      - api-gateway
    networks:
      - flowbit-network

volumes:
  mongodb_data:
  n8n_data:

networks:
  flowbit-network:
    driver: bridge

// ========================================
// packages/api-gateway/package.json
// ========================================
{
  "name": "flowbit-api-gateway",
  "version": "1.0.0",
  "description": "Flowbit API Gateway with multi-tenant support",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest",
    "seed": "node scripts/seed.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^7.0.3",
    "jsonwebtoken": "^9.0.0",
    "bcrypt": "^5.1.0",
    "cors": "^2.8.5",
    "helmet": "^6.1.5",
    "dotenv": "^16.0.3",
    "axios": "^1.4.0",
    "express-rate-limit": "^6.7.0"
  },
  "devDependencies": {
    "jest": "^29.5.0",
    "supertest": "^6.3.3",
    "nodemon": "^2.0.22"
  }
}

// ========================================
// packages/api-gateway/server.js
// ========================================
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const ticketRoutes = require('./routes/tickets');
const webhookRoutes = require('./routes/webhooks');
const userRoutes = require('./routes/users');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Routes
app.use('/auth', authRoutes);
app.use('/api', ticketRoutes);
app.use('/webhook', webhookRoutes);
app.use('/me', userRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://admin:password@localhost:27017/flowbit?authSource=admin', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
});

module.exports = app;

// ========================================
// packages/api-gateway/models/User.js
// ========================================
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  customerId: {
    type: String,
    required: true,
    index: true
  },
  role: {
    type: String,
    enum: ['Admin', 'User'],
    default: 'User'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);

// ========================================
// packages/api-gateway/models/Ticket.js
// ========================================
const mongoose = require('mongoose');

const ticketSchema = new mongoose.Schema({
  customerId: {
    type: String,
    required: true,
    index: true
  },
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed'],
    default: 'pending'
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

ticketSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Ticket', ticketSchema);

// ========================================
// packages/api-gateway/models/AuditLog.js
// ========================================
const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  action: {
    type: String,
    required: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  customerId: {
    type: String,
    required: true,
    index: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
});

module.exports = mongoose.model('AuditLog', auditLogSchema);

// ========================================
// packages/api-gateway/middleware/auth.js
// ========================================
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = {
      userId: user._id,
      email: user.email,
      customerId: user.customerId,
      role: user.role
    };
    
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

const tenantIsolation = (req, res, next) => {
  // Ensure all database queries are scoped to the user's tenant
  req.tenantFilter = { customerId: req.user.customerId };
  next();
};

module.exports = {
  authenticateToken,
  requireAdmin,
  tenantIsolation
};

// ========================================
// packages/api-gateway/middleware/audit.js
// ========================================
const AuditLog = require('../models/AuditLog');

const auditLog = (action) => {
  return async (req, res, next) => {
    const originalSend = res.send;
    
    res.send = function(data) {
      // Log the action after successful response
      if (res.statusCode >= 200 && res.statusCode < 300 && req.user) {
        AuditLog.create({
          action,
          userId: req.user.userId,
          customerId: req.user.customerId,
          details: {
            method: req.method,
            path: req.path,
            body: req.body,
            query: req.query
          }
        }).catch(err => console.error('Audit log error:', err));
      }
      
      originalSend.call(this, data);
    };
    
    next();
  };
};

module.exports = { auditLog };

// ========================================
// packages/api-gateway/routes/auth.js
// ========================================
const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { auditLog } = require('../middleware/audit');

const router = express.Router();

// Login endpoint
router.post('/login', auditLog('LOGIN'), async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { 
        userId: user._id,
        customerId: user.customerId,
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        customerId: user.customerId,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;

// ========================================
// packages/api-gateway/routes/users.js
// ========================================
const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const registry = require('../config/registry.json');

const router = express.Router();

// Get screens for the current user's tenant
router.get('/screens', authenticateToken, (req, res) => {
  try {
    const { customerId } = req.user;
    const screens = registry[customerId]?.screens || [];
    
    res.json({ screens });
  } catch (error) {
    console.error('Get screens error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get current user profile
router.get('/profile', authenticateToken, (req, res) => {
  res.json({
    user: {
      id: req.user.userId,
      email: req.user.email,
      customerId: req.user.customerId,
      role: req.user.role
    }
  });
});

module.exports = router;

// ========================================
// packages/api-gateway/routes/tickets.js
// ========================================
const express = require('express');
const axios = require('axios');
const Ticket = require('../models/Ticket');
const { authenticateToken, tenantIsolation } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');

const router = express.Router();

// Apply authentication and tenant isolation to all routes
router.use(authenticateToken);
router.use(tenantIsolation);

// Get all tickets for the current tenant
router.get('/tickets', async (req, res) => {
  try {
    const tickets = await Ticket.find(req.tenantFilter)
      .populate('createdBy', 'email')
      .sort({ createdAt: -1 });
    
    res.json({ tickets });
  } catch (error) {
    console.error('Get tickets error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create a new ticket and trigger n8n workflow
router.post('/tickets', auditLog('CREATE_TICKET'), async (req, res) => {
  try {
    const { title, description } = req.body;

    if (!title || !description) {
      return res.status(400).json({ error: 'Title and description required' });
    }

    // Create ticket in database
    const ticket = new Ticket({
      customerId: req.user.customerId,
      title,
      description,
      createdBy: req.user.userId
    });

    await ticket.save();

    // Trigger n8n workflow
    try {
      await axios.post(`${process.env.N8N_URL}/webhook/ticket-created`, {
        ticketId: ticket._id,
        customerId: req.user.customerId,
        title,
        description,
        callbackUrl: `${process.env.WEBHOOK_URL || 'http://localhost:3001'}/webhook/ticket-done`
      }, {
        headers: {
          'Authorization': `Basic ${Buffer.from('admin:password').toString('base64')}`
        }
      });
    } catch (n8nError) {
      console.error('n8n workflow trigger error:', n8nError.message);
      // Continue anyway - the ticket is created
    }

    res.status(201).json({ 
      ticket: {
        ...ticket.toJSON(),
        createdBy: { email: req.user.email }
      }
    });
  } catch (error) {
    console.error('Create ticket error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get specific ticket
router.get('/tickets/:id', async (req, res) => {
  try {
    const ticket = await Ticket.findOne({
      _id: req.params.id,
      ...req.tenantFilter
    }).populate('createdBy', 'email');

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    res.json({ ticket });
  } catch (error) {
    console.error('Get ticket error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;

// ========================================
// packages/api-gateway/routes/webhooks.js
// ========================================
const express = require('express');
const Ticket = require('../models/Ticket');

const router = express.Router();

// Webhook endpoint for n8n callbacks
router.post('/ticket-done', async (req, res) => {
  try {
    const { ticketId, customerId, status } = req.body;
    const sharedSecret = req.headers['x-webhook-secret'];

    // Verify shared secret
    if (sharedSecret !== process.env.N8N_WEBHOOK_SECRET) {
      return res.status(401).json({ error: 'Invalid webhook secret' });
    }

    if (!ticketId || !customerId || !status) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Update ticket status
    const ticket = await Ticket.findOneAndUpdate(
      { _id: ticketId, customerId },
      { status, updatedAt: new Date() },
      { new: true }
    );

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    // In a real application, you would notify the UI here
    // For now, we'll just log the update
    console.log(`Ticket ${ticketId} updated to status: ${status}`);

    res.json({ success: true, ticket });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;

// ========================================
// packages/api-gateway/config/registry.json
// ========================================
{
  "LogisticsCo": {
    "screens": [
      {
        "id": "support-tickets",
        "name": "Support Tickets",
        "url": "http://localhost:3002/remoteEntry.js",
        "scope": "supportTickets",
        "module": "./App",
        "path": "/tickets"
      }
    ]
  },
  "RetailGmbH": {
    "screens": [
      {
        "id": "support-tickets",
        "name": "Support Tickets",
        "url": "http://localhost:3002/remoteEntry.js",
        "scope": "supportTickets",
        "module": "./App",
        "path": "/tickets"
      }
    ]
  }
}

// ========================================
// packages/api-gateway/scripts/seed.js
// ========================================
const mongoose = require('mongoose');
const User = require('../models/User');
require('dotenv').config();

async function seedDatabase() {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://admin:password@localhost:27017/flowbit?authSource=admin');
    
    // Clear existing users
    await User.deleteMany({});
    
    // Create tenant admins
    const tenants = [
      {
        email: 'admin@logisticsco.com',
        password: 'admin123',
        customerId: 'LogisticsCo',
        role: 'Admin'
      },
      {
        email: 'admin@retailgmbh.com',
        password: 'admin123',
        customerId: 'RetailGmbH',
        role: 'Admin'
      }
    ];

    for (const tenant of tenants) {
      const user = new User(tenant);
      await user.save();
      console.log(`Created user: ${tenant.email} for tenant: ${tenant.customerId}`);
    }

    console.log('Database seeded successfully');
    process.exit(0);
  } catch (error) {
    console.error('Seed error:', error);
    process.exit(1);
  }
}

seedDatabase();

// ========================================
// packages/api-gateway/Dockerfile
// ========================================
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3001

CMD ["npm", "start"]

// ========================================
// packages/api-gateway/__tests__/tenant-isolation.test.js
// ========================================
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../server');
const User = require('../models/User');
const Ticket = require('../models/Ticket');

describe('Tenant Isolation', () => {
  let tenantAAdmin, tenantBAdmin, tenantAToken, tenantBToken;

  beforeAll(async () => {
    // Connect to test database
    await mongoose.connect('mongodb://admin:password@localhost:27017/flowbit_test?authSource=admin');
    
    // Create test users
    tenantAAdmin = new User({
      email: 'admin-a@test.com',
      password: 'password123',
      customerId: 'TenantA',
      role: 'Admin'
    });
    await tenantAAdmin.save();

    tenantBAdmin = new User({
      email: 'admin-b@test.com',
      password: 'password123',
      customerId: 'TenantB',
      role: 'Admin'
    });
    await tenantBAdmin.save();

    // Get tokens
    const responseA = await request(app)
      .post('/auth/login')
      .send({ email: 'admin-a@test.com', password: 'password123' });
    tenantAToken = responseA.body.token;

    const responseB = await request(app)
      .post('/auth/login')
      .send({ email: 'admin-b@test.com', password: 'password123' });
    tenantBToken = responseB.body.token;
  });

  afterAll(async () => {
    await User.deleteMany({});
    await Ticket.deleteMany({});
    await mongoose.connection.close();
  });

  it('should prevent Admin from Tenant A accessing Tenant B data', async () => {
    // Create ticket for Tenant B
    const ticketB = new Ticket({
      customerId: 'TenantB',
      title: 'Tenant B Ticket',
      description: 'This belongs to Tenant B',
      createdBy: tenantBAdmin._id
    });
    await ticketB.save();

    // Try to access Tenant B's ticket using Tenant A's token
    const response = await request(app)
      .get('/api/tickets')
      .set('Authorization', `Bearer ${tenantAToken}`);

    expect(response.status).toBe(200);
    expect(response.body.tickets).toHaveLength(0);
    expect(response.body.tickets.find(t => t._id === ticketB._id)).toBeUndefined();
  });

  it('should allow Admin to access their own tenant data', async () => {
    // Create ticket for Tenant A
    const ticketA = new Ticket({
      customerId: 'TenantA',
      title: 'Tenant A Ticket',
      description: 'This belongs to Tenant A',
      createdBy: tenantAAdmin._id
    });
    await ticketA.save();

    // Access Tenant A's ticket using Tenant A's token
    const response = await request(app)
      .get('/api/tickets')
      .set('Authorization', `Bearer ${tenantAToken}`);

    expect(response.status).toBe(200);
    expect(response.body.tickets).toHaveLength(1);
    expect(response.body.tickets[0].customerId).toBe('TenantA');
  });
});

// ========================================
// packages/react-shell/package.json
// ========================================
{
  "name": "flowbit-react-shell",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "@testing-library/jest-dom": "^5.16.4",
    "@testing-library/react": "^13.3.0",
    "@testing-library/user-event": "^13.5.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.3.0",
    "react-scripts": "5.0.1",
    "axios": "^1.4.0",
    "tailwindcss": "^3.3.0",
    "autoprefixer": "^10.4.14",
    "postcss": "^8.4.24"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "eslintConfig": {
    "extends": [
      "react-app",
      "react-app/jest"
    ]
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  },
  "devDependencies": {
    "@module-federation/webpack": "^2.2.0"
  }
}

// ========================================
// packages/react-shell/webpack.config.js
// ========================================
const ModuleFederationPlugin = require('@module-federation/webpack');

module.exports = {
  mode: 'development',
  devServer: {
    port: 3000,
    historyApiFallback: true,
  },
  plugins: [
    new ModuleFederationPlugin({
      name: 'shell',
      remotes: {
        supportTickets: 'supportTickets@http://localhost:3002/remoteEntry.js',
      },
    }),
  ],
};

// ========================================
// packages/react-shell/src/App.js
// ========================================
import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import { AuthProvider, useAuth } from './context/AuthContext';
import './App.css';

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="App">
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/dashboard/*" element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            } />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </div>
      </Router>
    </AuthProvider>
  );
}

function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();
  
  if (loading) {
    return <div className="flex justify-center items-center h-screen">Loading...</div>;
  }
  
  return isAuthenticated ? children : <Navigate to="/login" />;
}

export default App;

// ========================================
// packages/react-shell/src/components/Login.js
// ========================================
import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';

function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      await login(email, password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Sign in to Flowbit
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Multi-tenant workflow management
          </p>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                required
                className="relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Email address"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                className="relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          {error && (
            <div className="text-red-600 text-sm text-center">{error}</div>
          )}

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
          </div>

          <div className="text-sm text-gray-600 text-center">
            <p>Demo accounts:</p>
            <p>admin@logisticsco.com / admin123</p>
            <p>admin@retailgmbh.com / admin123</p>
          </div>
        </form>
      </div>
    </div>
  );
}

export default Login;

// ========================================
// packages/react-shell/src/components/Dashboard.js
// ========================================
import React, { useState, useEffect, Suspense } from 'react';
import { Routes, Route } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import Sidebar from './Sidebar';
import api from '../services/api';

const RemoteApp = React.lazy(() => import('supportTickets/App'));

function Dashboard() {
  const { user } = useAuth();
  const [screens, setScreens] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchScreens();
  }, []);

  const fetchScreens = async () => {
    try {
      const response = await api.get('/me/screens');
      setScreens(response.data.screens);
    } catch (error) {
      console.error('Error fetching screens:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="flex justify-center items-center h-screen">Loading...</div>;
  }

  return (
    <div className="flex h-screen bg-gray-100">
      <Sidebar screens={screens} user={user} />
      <main className="flex-1 overflow-y-auto">
        <div className="p-6">
          <Routes>
            <Route path="/" element={<WelcomeScreen user={user} />} />
            <Route path="/tickets/*" element={
              <Suspense fallback={<div>Loading Support Tickets...</div>}>
                <RemoteApp />
              </Suspense>
            } />
          </Routes>
        </div>
      </main>
    </div>
  );
}

function WelcomeScreen({ user }) {
  return (
    <div className="max-w-7xl mx-auto">
      <div className="bg-white shadow rounded-lg p-6">
        <h1 className="text-2xl font-bold text-gray-900 mb-4">
          Welcome to Flowbit
        </h1>
        <p className="text-gray-600 mb-6">
          Multi-tenant workflow management system
        </p>
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h2 className="text-lg font-semibold text-blue-900 mb-2">
            Current Tenant: {user.customerId}
          </h2>
          <p className="text-blue-700">
            Logged in as: {user.email} ({user.role})
          </p>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;

// ========================================
// packages/react-shell/src/components/Sidebar.js
// ========================================
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function Sidebar({ screens, user }) {
  const location = useLocation();
  const { logout } = useAuth();

  return (
    <div className="bg-gray-800 text-white w-64 min-h-screen flex flex-col">
      <div className="p-4">
        <h1 className="text-xl font-bold">Flowbit</h1>
        <p className="text-gray-400 text-sm">{user.customerId}</p>
      </div>
      
      <nav className="flex-1 px-4 py-6 space-y-2">
        <Link
          to="/dashboard"
          className={`block px-3 py-2 rounded-md text-sm font-medium ${
            location.pathname === '/dashboard' 
              ? 'bg-gray-900 text-white' 
              : 'text-gray-300 hover:bg-gray-700'
          }`}
        >
          Dashboard
        </Link>
        
        {screens.map((screen) => (
          <Link
            key={screen.id}
            to={`/dashboard${screen.path}`}
            className={`block px-3 py-2 rounded-md text-sm font-medium ${
              location.pathname.startsWith(`/dashboard${screen.path}`)
                ? 'bg-gray-900 text-white'
                : 'text-gray-300 hover:bg-gray-700'
            }`}
          >
            {screen.name}
          </Link>
        ))}
      </nav>

      <div className="p-4 border-t border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium">{user.email}</p>
            <p className="text-xs text-gray-400">{user.role}</p>
          </div>
          <button
            onClick={logout}
            className="text-gray-400 hover:text-white text-sm"
          >
            Logout
          </button>
        </div>
      </div>
    </div>
  );
}

export default Sidebar;

// ========================================
// packages/react-shell/src/context/AuthContext.js
// ========================================
import React, { createContext, useContext, useReducer, useEffect } from 'react';
import api from '../services/api';

const AuthContext = createContext();

const authReducer = (state, action) => {
  switch (action.type) {
    case 'LOGIN_SUCCESS':
      return {
        ...state,
        isAuthenticated: true,
        user: action.payload.user,
        token: action.payload.token,
        loading: false,
      };
    case 'LOGOUT':
      return {
        ...state,
        isAuthenticated: false,
        user: null,
        token: null,
        loading: false,
      };
    case 'SET_LOADING':
      return {
        ...state,
        loading: action.payload,
      };
    default:
      return state;
  }
};

const initialState = {
  isAuthenticated: false,
  user: null,
  token: null,
  loading: true,
};

export function AuthProvider({ children }) {
  const [state, dispatch] = useReducer(authReducer, initialState);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    
    if (token && user) {
      dispatch({
        type: 'LOGIN_SUCCESS',
        payload: {
          token,
          user: JSON.parse(user),
        },
      });
    } else {
      dispatch({ type: 'SET_LOADING', payload: false });
    }
  }, []);

  const login = async (email, password) => {
    try {
      const response = await api.post('/auth/login', { email, password });
      const { token, user } = response.data;
      
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(user));
      
      dispatch({
        type: 'LOGIN_SUCCESS',
        payload: { token, user },
      });
    } catch (error) {
      throw new Error(error.response?.data?.error || 'Login failed');
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    dispatch({ type: 'LOGOUT' });
  };

  return (
    <AuthContext.Provider value={{
      ...state,
      login,
      logout,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// ========================================
// packages/react-shell/src/services/api.js
// ========================================
import axios from 'axios';

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:3001',
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;

// ========================================
// packages/react-shell/src/App.css
// ========================================
@tailwind base;
@tailwind components;
@tailwind utilities;

.App {
  text-align: left;
}

// ========================================
// packages/react-shell/tailwind.config.js
// ========================================
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}

// ========================================
// packages/react-shell/Dockerfile
// ========================================
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

RUN npm run build

FROM nginx:alpine
COPY --from=0 /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]

// ========================================
// packages/react-shell/nginx.conf
// ========================================
server {
    listen 3000;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    location /static/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}

// ========================================
// packages/support-tickets-app/package.json
// ========================================
{
  "name": "flowbit-support-tickets",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-scripts": "5.0.1",
    "axios": "^1.4.0",
    "tailwindcss": "^3.3.0",
    "autoprefixer": "^10.4.14",
    "postcss": "^8.4.24"
  },
  "scripts": {
    "start": "webpack serve --mode development",
    "build": "webpack --mode production",
    "test": "react-scripts test"
  },
  "devDependencies": {
    "@module-federation/webpack": "^2.2.0",
    "webpack": "^5.88.0",
    "webpack-cli": "^5.1.4",
    "webpack-dev-server": "^4.15.1",
    "html-webpack-plugin": "^5.5.3",
    "babel-loader": "^9.1.2",
    "@babel/core": "^7.22.5",
    "@babel/preset-react": "^7.22.5"
  }
}

// ========================================
// packages/support-tickets-app/webpack.config.js
// ========================================
const HtmlWebpackPlugin = require('html-webpack-plugin');
const ModuleFederationPlugin = require('@module-federation/webpack');

module.exports = {
  mode: 'development',
  devServer: {
    port: 3002,
    historyApiFallback: true,
    headers: {
      'Access-Control-Allow-Origin': '*',
    },
  },
  module: {
    rules: [
      {
        test: /\.jsx?$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-react'],
          },
        },
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader', 'postcss-loader'],
      },
    ],
  },
  plugins: [
    new ModuleFederationPlugin({
      name: 'supportTickets',
      filename: 'remoteEntry.js',
      exposes: {
        './App': './src/App',
      },
      shared: {
        react: { singleton: true },
        'react-dom': { singleton: true },
      },
    }),
    new HtmlWebpackPlugin({
      template: './public/index.html',
    }),
  ],
};

// ========================================
// packages/support-tickets-app/src/App.js
// ========================================
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:3001',
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

function App() {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newTicket, setNewTicket] = useState({ title: '', description: '' });

  useEffect(() => {
    fetchTickets();
    // Poll for updates every 5 seconds
    const interval = setInterval(fetchTickets, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchTickets = async () => {
    try {
      const response = await api.get('/api/tickets');
      setTickets(response.data.tickets);
    } catch (error) {
      console.error('Error fetching tickets:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateTicket = async (e) => {
    e.preventDefault();
    try {
      const response = await api.post('/api/tickets', newTicket);
      setTickets([response.data.ticket, ...tickets]);
      setNewTicket({ title: '', description: '' });
      setShowCreateForm(false);
    } catch (error) {
      console.error('Error creating ticket:', error);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'pending': return 'bg-yellow-100 text-yellow-800';
      case 'processing': return 'bg-blue-100 text-blue-800';
      case 'completed': return 'bg-green-100 text-green-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  if (loading) {
    return <div className="flex justify-center items-center h-64">Loading tickets...</div>;
  }

  return (
    <div className="max-w-7xl mx-auto">
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex justify-between items-center">
            <h1 className="text-2xl font-bold text-gray-900">Support Tickets</h1>
            <button
              onClick={() => setShowCreateForm(true)}
              className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md text-sm font-medium"
            >
              Create Ticket
            </button>
          </div>
        </div>

        {showCreateForm && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 w-full max-w-md">
              <h2 className="text-lg font-bold mb-4">Create New Ticket</h2>
              <form onSubmit={handleCreateTicket}>
                <div className="mb-4">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Title
                  </label>
                  <input
                    type="text"
                    required
                    value={newTicket.title}
                    onChange={(e) => setNewTicket({ ...newTicket, title: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
                <div className="mb-4">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Description
                  </label>
                  <textarea
                    required
                    rows="4"
                    value={newTicket.description}
                    onChange={(e) => setNewTicket({ ...newTicket, description: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
                <div className="flex justify-end space-x-2">
                  <button
                    type="button"
                    onClick={() => setShowCreateForm(false)}
                    className="px-4 py-2 text-gray-600 hover:text-gray-800"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md"
                  >
                    Create
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        <div className="p-6">
          {tickets.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-gray-500">No tickets found. Create your first ticket!</p>
            </div>
          ) : (
            <div className="space-y-4">
              {tickets.map((ticket) => (
                <div key={ticket._id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <h3 className="text-lg font-medium text-gray-900">{ticket.title}</h3>
                      <p className="text-gray-600 mt-1">{ticket.description}</p>
                      <div className="mt-2 flex items-center space-x-4 text-sm text-gray-500">
                        <span>Created by: {ticket.createdBy?.email}</span>
                        <span>Created: {new Date(ticket.createdAt).toLocaleDateString()}</span>
                      </div>
                    </div>
                    <div className="ml-4">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(ticket.status)}`}>
                        {ticket.status}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;

// ========================================
// packages/support-tickets-app/src/App.css
// ========================================
@tailwind base;
@tailwind components;
@tailwind utilities;

// ========================================
// packages/support-tickets-app/tailwind.config.js
// ========================================
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}

// ========================================
// packages/support-tickets-app/public/index.html
// ========================================
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Support Tickets App</title>
</head>
<body>
    <div id="root"></div>
</body>
</html>

// ========================================
// packages/support-tickets-app/Dockerfile
// ========================================
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

RUN npm run build

FROM nginx:alpine
COPY --from=0 /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3002

CMD ["nginx", "-g", "daemon off;"]

// ========================================
// packages/support-tickets-app/nginx.conf
// ========================================
server {
    listen 3002;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    location /remoteEntry.js {
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods GET;
        add_header Access-Control-Allow-Headers Content-Type;
    }
}

// ========================================
// cypress/e2e/tenant-isolation.cy.js
// ========================================
describe('Tenant Isolation E2E Test', () => {
  beforeEach(() => {
    cy.visit('http://localhost:3000');
  });

  it('should demonstrate complete tenant isolation flow', () => {
    // Test Tenant A
    cy.get('[data-testid="email"]').type('admin@logisticsco.com');
    cy.get('[data-testid="password"]').type('admin123');
    cy.get('[data-testid="login-button"]').click();
    
    // Verify tenant A dashboard
    cy.contains('LogisticsCo').should('be.visible');
    
    // Create ticket for tenant A
    cy.get('[data-testid="create-ticket"]').click();
    cy.get('[data-testid="ticket-title"]').type('LogisticsCo Ticket');
    cy.get('[data-testid="ticket-description"]').type('This is a LogisticsCo ticket');
    cy.get('[data-testid="submit-ticket"]').click();
    
    // Verify ticket appears
    cy.contains('LogisticsCo Ticket').should('be.visible');
    
    // Logout
    cy.get('[data-testid="logout"]').click();
    
    // Test Tenant B
    cy.get('[data-testid="email"]').clear().type('admin@retailgmbh.com');
    cy.get('[data-testid="password"]').clear().type('admin123');
    cy.get('[data-testid="login-button"]').click();
    
    // Verify tenant B dashboard
    cy.contains('RetailGmbH').should('be.visible');
    
    // Verify tenant A's ticket is NOT visible
    cy.contains('LogisticsCo Ticket').should('not.exist');
    
    // Create ticket for tenant B
    cy.get('[data-testid="create-ticket"]').click();
    cy.get('[data-testid="ticket-title"]').type('RetailGmbH Ticket');
    cy.get('[data-testid="ticket-description"]').type('This is a RetailGmbH ticket');
    cy.get('[data-testid="submit-ticket"]').click();
    
    // Verify only tenant B's ticket appears
    cy.contains('RetailGmbH Ticket').should('be.visible');
    cy.contains('LogisticsCo Ticket').should('not.exist');
  });
});

// ========================================
// cypress.config.js
// ========================================
const { defineConfig } = require('cypress');

module.exports = defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3000',
    setupNodeEvents(on, config) {
      // implement node event listeners here
    },
  },
});

// ========================================
// .github/workflows/ci.yml
// ========================================
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      mongodb:
        image: mongo:5.0
        ports:
          - 27017:27017
        env:
          MONGO_INITDB_ROOT_USERNAME: admin
          MONGO_INITDB_ROOT_PASSWORD: password
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Use Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'
        cache-dependency-path: 'packages/api-gateway/package-lock.json'
    
    - name: Install dependencies
      run: |
        cd packages/api-gateway
        npm ci
    
    - name: Run linter
      run: |
        cd packages/api-gateway
        npm run lint
    
    - name: Run tests
      run: |
        cd packages/api-gateway
        npm test
      env:
        MONGODB_URI: mongodb://admin:password@localhost:27017/flowbit_test?authSource=admin
        JWT_SECRET: test-jwt-secret
        N8N_WEBHOOK_SECRET: test-webhook-secret

// ========================================
// README.md
// ========================================
# Flowbit - Multi-Tenant Workflow Management System

A comprehensive multi-tenant workflow management system built with React micro-frontends, Node.js API, and n8n workflow automation.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    React Shell (Port 3000)                  │
│  ┌─────────────────┐  ┌─────────────────────────────────────┐│
│  │   Auth/Login    │  │     Dynamic Micro-Frontend          ││
│  │   - JWT Auth    │  │   - SupportTicketsApp (Port 3002)   ││
│  │   - RBAC        │  │   - Tenant-specific screens         ││
│  └─────────────────┘  └─────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  API Gateway (Port 3001)                    │
│  ┌─────────────────┐  ┌─────────────────────────────────────┐│
│  │   Auth API      │  │         Tickets API                 ││
│  │   - JWT verify  │  │   - Tenant isolation middleware     ││
│  │   - /me/screens │  │   - POST /api/tickets               ││
│  │                 │  │   - Webhook /webhook/ticket-done    ││
│  └─────────────────┘  └─────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     External Services                       │
│  ┌─────────────────┐  ┌─────────────────────────────────────┐│
│  │MongoDB(27017)   │  │          n8n (Port 5678)            ││
│  │  - Multi-tenant │  │   - Workflow engine                 ││
│  │  - Collections  │  │   - Webhook callbacks               ││
│  │    with         │  │   - Docker container                ││
│  │  customerId     │  │                                     ││
│  └─────────────────┘  └─────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Features

### ✅ Core Requirements
- **R1**: JWT Authentication with bcrypt password hashing and RBAC
- **R2**: Strict tenant data isolation with MongoDB customerId scoping
- **R3**: Hard-coded registry system for tenant-specific screens
- **R4**: Dynamic micro-frontend loading via Webpack Module Federation
- **R5**: Complete n8n workflow integration with webhook callbacks
- **R6**: Fully containerized development environment

### ✅ Bonus Features
- **Audit logging** for all ticket operations
- **Cypress E2E tests** for tenant isolation
- **GitHub Actions CI/CD** with automated testing
- **Real-time updates** with polling mechanism

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Node.js 18+ (for local development)
- Git

### 1. Clone and Setup
```bash
git clone <repository-url>
cd flowbit
```

### 2. Start All Services
```bash
# Start all containers
docker-compose up -d

# Wait for services to be ready (about 30 seconds)
docker-compose logs -f
```

### 3. Seed Database
```bash
# Seed with tenant data
docker-compose exec api-gateway npm run seed
```

### 4. Access the Application
- **Main App**: http://localhost:3000
- **API Gateway**: http://localhost:3001
- **n8n Workflow Engine**: http://localhost:5678 (admin/password)
- **MongoDB**: localhost:27017

### 5. Demo Accounts
- **LogisticsCo**: admin@logisticsco.com / admin123
- **RetailGmbH**: admin@retailgmbh.com / admin123

## Testing

### Unit Tests
```bash
cd packages/api-gateway
npm test
```

### E2E Tests
```bash
npx cypress open
```

### Manual Testing Flow
1. Login as LogisticsCo admin
2. Create a support ticket
3. Verify n8n workflow triggers
4. Check ticket status updates
5. Login as RetailGmbH admin
6. Verify tenant isolation (no LogisticsCo tickets visible)

## Development

### Local Development (without Docker)
```bash
# Terminal 1 - MongoDB
mongod --dbpath ./data

# Terminal 2 -
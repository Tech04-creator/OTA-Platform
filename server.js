const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const mqtt = require('mqtt');

const app = express();
const PORT = process.env.PORT || 3002;
const JWT_SECRET = 'your-secret-key-change-in-production';

// MQTT Configuration
const MQTT_BROKER = process.env.MQTT_BROKER || 'mqtt://localhost:1883';
const MQTT_TOPIC = 'ota/firmware/updates';

// MQTT Client
let mqttClient = null;

// Initialize MQTT connection
function initializeMQTT() {
  try {
    mqttClient = mqtt.connect(MQTT_BROKER, {
      clientId: 'ota-platform-server',
      clean: true,
      connectTimeout: 4000,
      reconnectPeriod: 1000,
    });

    mqttClient.on('connect', () => {
      console.log('✅ MQTT Connected to broker');
    });

    mqttClient.on('error', (err) => {
      console.log('❌ MQTT Error:', err.message);
    });

    mqttClient.on('close', () => {
      console.log('🔌 MQTT Connection closed');
    });

  } catch (error) {
    console.log('⚠️ MQTT not available:', error.message);
  }
}

// Send MQTT notification
function sendMQTTNotification(message) {
  if (mqttClient && mqttClient.connected) {
    const payload = {
      timestamp: new Date().toISOString(),
      message: message,
      type: 'firmware_update'
    };
    
    mqttClient.publish(MQTT_TOPIC, JSON.stringify(payload), (err) => {
      if (err) {
        console.log('❌ MQTT Publish error:', err);
      } else {
        console.log('📡 MQTT Notification sent:', message);
      }
    });
  }
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: function (req, file, cb) {
    // Accept firmware files and text files
    if (file.mimetype === 'application/octet-stream' || 
        file.originalname.endsWith('.bin') || 
        file.originalname.endsWith('.hex') ||
        file.originalname.endsWith('.firmware') ||
        file.originalname.endsWith('.txt') ||
        file.mimetype === 'text/plain') {
      cb(null, true);
    } else {
      cb(new Error('Only firmware files (.bin, .hex, .firmware) and text files (.txt) are allowed!'), false);
    }
  }
});

// Database initialization
const db = new sqlite3.Database('ota_platform.db');

// Create tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'User',
    status TEXT DEFAULT 'Active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Firmware uploads table
  db.run(`CREATE TABLE IF NOT EXISTS firmware_uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    train_number TEXT NOT NULL,
    firmware_version TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER,
    description TEXT,
    uploaded_by INTEGER,
    status TEXT DEFAULT 'Pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uploaded_by) REFERENCES users (id)
  )`);

  // Insert default admin user
  const adminPassword = bcrypt.hashSync('admin', 10);
  db.run(`INSERT OR IGNORE INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`, 
    ['Admin User', 'admin@example.com', adminPassword, 'Admin']);
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'OTA Platform API is running',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  });
});

// Get current user
app.get('/api/user', authenticateToken, (req, res) => {
  db.get('SELECT id, name, email, role, status FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(user);
  });
});

// Get all users
app.get('/api/users', authenticateToken, (req, res) => {
  db.all('SELECT id, name, email, role, status, created_at FROM users', (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(users);
  });
});

// Add new user
app.post('/api/users', authenticateToken, (req, res) => {
  const { name, email, password, role } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
    [name, email, hashedPassword, role], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ id: this.lastID, message: 'User created successfully' });
  });
});

// Update user
app.put('/api/users/:id', authenticateToken, (req, res) => {
  const { name, email, role, status } = req.body;
  const userId = req.params.id;

  db.run('UPDATE users SET name = ?, email = ?, role = ?, status = ? WHERE id = ?',
    [name, email, role, status, userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ message: 'User updated successfully' });
  });
});

// Delete user
app.delete('/api/users/:id', authenticateToken, (req, res) => {
  const userId = req.params.id;

  db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ message: 'User deleted successfully' });
  });
});

// Upload firmware (with authentication)
app.post('/api/upload', authenticateToken, upload.single('firmware'), (req, res) => {
  const { trainNumber, firmwareVersion, description } = req.body;
  const file = req.file;

  if (!file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const fileSize = file.size;
  const fileName = file.originalname;
  const filePath = file.path;

  db.run(`INSERT INTO firmware_uploads
    (train_number, firmware_version, file_name, file_path, file_size, description, uploaded_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [trainNumber, firmwareVersion, fileName, filePath, fileSize, description, req.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({
        id: this.lastID,
        message: 'Firmware uploaded successfully',
        file: {
          name: fileName,
          size: fileSize,
          path: filePath
        }
      });
    });
});

// Upload firmware (test endpoint - no authentication required)
app.post('/api/upload-test', upload.single('firmware'), (req, res) => {
  const { trainNumber, firmwareVersion, description } = req.body;
  const file = req.file;

  if (!file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const fileSize = file.size;
  const fileName = file.originalname;
  const filePath = file.path;

  db.run(`INSERT INTO firmware_uploads
    (train_number, firmware_version, file_name, file_path, file_size, description, uploaded_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [trainNumber, firmwareVersion, fileName, filePath, fileSize, description, 1], // Use admin user ID 1
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      // Send MQTT notification
      const notificationMessage = `New firmware uploaded: ${fileName} for Train ${trainNumber} (v${firmwareVersion})`;
      sendMQTTNotification(notificationMessage);
      
      res.json({
        id: this.lastID,
        message: 'Firmware uploaded successfully',
        file: {
          name: fileName,
          size: fileSize,
          path: filePath
        }
      });
    });
});

// Get all firmware uploads
app.get('/api/firmware', authenticateToken, (req, res) => {
  db.all(`SELECT f.*, u.name as uploaded_by_name 
    FROM firmware_uploads f 
    LEFT JOIN users u ON f.uploaded_by = u.id 
    ORDER BY f.created_at DESC`, (err, uploads) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(uploads);
  });
});

// Download firmware
app.get('/api/firmware/:id/download', authenticateToken, (req, res) => {
  const uploadId = req.params.id;

  db.get('SELECT file_path, file_name FROM firmware_uploads WHERE id = ?', [uploadId], (err, upload) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!upload) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.download(upload.file_path, upload.file_name);
  });
});

// Delete firmware upload
app.delete('/api/firmware/:id', authenticateToken, (req, res) => {
  const uploadId = req.params.id;

  db.get('SELECT file_path FROM firmware_uploads WHERE id = ?', [uploadId], (err, upload) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!upload) {
      return res.status(404).json({ error: 'Upload not found' });
    }

    // Delete file from filesystem
    if (fs.existsSync(upload.file_path)) {
      fs.unlinkSync(upload.file_path);
    }

    // Delete from database
    db.run('DELETE FROM firmware_uploads WHERE id = ?', [uploadId], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ message: 'Firmware deleted successfully' });
    });
  });
});

// Dashboard stats
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
  db.get('SELECT COUNT(*) as total_uploads FROM firmware_uploads', (err, uploads) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    db.get('SELECT COUNT(*) as total_users FROM users', (err, users) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      db.get('SELECT COUNT(*) as active_uploads FROM firmware_uploads WHERE status = "Active"', (err, active) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }

        res.json({
          totalUploads: uploads.total_uploads,
          totalUsers: users.total_users,
          activeUploads: active.active_uploads
        });
      });
    });
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error(error.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API available at http://localhost:${PORT}/api`);
  
  // Initialize MQTT connection
  initializeMQTT();
}); 
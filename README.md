# OTA-Platform
A Node.js backend for the OTA (Over-The-Air) firmware update platform.

## Features

- **Authentication** - JWT-based user authentication
- **File Upload** - Secure firmware file uploads with validation
- **Database** - SQLite database for data persistence
- **User Management** - CRUD operations for users
- **Firmware Management** - Upload, download, and delete firmware files
- **Dashboard Stats** - Real-time statistics

## Setup

1. **Install dependencies:**
   ```bash
   cd backend
   npm install
   ```

2. **Start the server:**
   ```bash
   npm start
   # or for development with auto-restart:
   npm run dev
   ```

3. **Access the API:**
   - Server runs on `http://localhost:3002`
- API endpoints available at `http://localhost:3002/api`

## Default Admin User

- **Email:** `admin@example.com`
- **Password:** `admin`

## API Endpoints

### Authentication
- `POST /api/login` - User login
- `GET /api/user` - Get current user info

### Users Management
- `GET /api/users` - Get all users
- `POST /api/users` - Create new user
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user

### Firmware Management
- `POST /api/upload` - Upload firmware file
- `GET /api/firmware` - Get all firmware uploads
- `GET /api/firmware/:id/download` - Download firmware file
- `DELETE /api/firmware/:id` - Delete firmware upload

### Dashboard
- `GET /api/dashboard/stats` - Get dashboard statistics

## Database Schema

### Users Table
- `id` - Primary key
- `name` - User's full name
- `email` - Unique email address
- `password` - Hashed password
- `role` - User role (Admin, User, Viewer)
- `status` - User status (Active, Inactive)
- `created_at` - Timestamp

### Firmware Uploads Table
- `id` - Primary key
- `train_number` - Train identifier
- `firmware_version` - Firmware version
- `file_name` - Original filename
- `file_path` - Server file path
- `file_size` - File size in bytes
- `description` - Upload description
- `uploaded_by` - User ID who uploaded
- `status` - Upload status (Pending, Active, Failed)
- `created_at` - Timestamp

## File Upload

The backend accepts firmware files with extensions:
- `.bin`
- `.hex`
- `.firmware`

Files are stored in the `uploads/` directory with unique names.

## Security Features

- **Password Hashing** - bcrypt for secure password storage
- **JWT Authentication** - Token-based authentication
- **File Validation** - Only firmware files accepted
- **CORS** - Cross-origin resource sharing enabled
- **Error Handling** - Comprehensive error responses

## Environment Variables

- `PORT` - Server port (default: 3001)
- `JWT_SECRET` - Secret key for JWT tokens (change in production)

## Development

For development with auto-restart:
```bash
npm run dev
```

## Production

For production deployment:
1. Change `JWT_SECRET` to a secure random string
2. Use environment variables for configuration
3. Set up proper logging
4. Configure HTTPS
5. Set up database backups

## API Usage Examples

### Login
```javascript
fetch('/api/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'admin@example.com',
    password: 'admin'
  })
})
```

### Upload Firmware
```javascript
const formData = new FormData();
formData.append('firmware', file);
formData.append('trainNumber', '12345');
formData.append('firmwareVersion', 'v1.2.3');
formData.append('description', 'Updated firmware');

fetch('/api/upload', {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${token}` },
  body: formData
})
```

### Get Users
```javascript
fetch('/api/users', {
  headers: { 'Authorization': `Bearer ${token}` }
})
``` 

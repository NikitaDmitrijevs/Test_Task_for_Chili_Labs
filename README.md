# User Management RESTful API

A production-ready RESTful API with real-time WebSocket notifications for user management. Built with Flask, featuring JWT authentication, OAuth 2.0 style tokens, and MySQL database.

## Features

- **Secure Authentication** - JWT tokens with OAuth 2.0 style access/refresh tokens
- **User Management** - Registration, login, profile management, and account deletion
- **Avatar Upload** - Image upload with validation and storage
- **Real-time Notifications** - WebSocket notifications for avatar changes
- **MySQL Database** - Production-ready database with SQLAlchemy ORM
- **RESTful API** - Clean REST endpoints with JSend response format
- **Testing Interface** - Built-in web interface for API testing

## Tech Stack

- **Backend**: Flask, Flask-SocketIO
- **Database**: MySQL with SQLAlchemy ORM
- **Authentication**: JWT (Flask-JWT-Extended)
- **WebSocket**: Socket.IO with eventlet
- **File Upload**: Werkzeug secure upload
- **Password Hashing**: bcrypt# Test_Task_for_Chili_Labs

## Setup

### 1. Clone the repository

```bash
https://github.com/NikitaDmitrijevs/Test_Task_for_Chili_Labs.git
```

### 2. Install Python packages

Create a virtual environment and install dependencies:

```bash
python -m venv venv
```

**On Windows:**
```powershell
venv\Scripts\Activate.ps1
```

**Install requirements:**
```bash
pip install -r requirements.txt
```

### 3. Create .env file

```python
# Flask Configuration
SECRET_KEY=ZxQ9wK8vT7rY6uI5pO4aN3bM2cV1dE0fG7hJ8kL9jH6gF5dS4aP3qW2eR1tY0
JWT_SECRET_KEY=mN2bV1cX9zQ8wK7yJ6uH5iG4fD3sA2pL1oK9jI8uH7yG6tF5rD4eW3qA2

# MySQL Configuration
DB_HOST=localhost
DB_USER=YOUR_DB_USER
DB_PASSWORD=YOUR_DB_PASSWORD
DB_NAME=YOUR_DB_NAME
DB_PORT=3306
```

#### 4. Run application

Run the Flask application:

```bash
python app.py
```

Then open your browser and navigate to:
```
http://127.0.0.1:5000
```

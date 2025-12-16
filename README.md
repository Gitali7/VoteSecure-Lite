# VoteSecure Lite 🗳️

**VoteSecure Lite** is a basic yet robust online voting system built with Python and Flask. Designed for educational purposes, it demonstrates how to implement a safe, fair, and digital ballot handling system with a focus on code release quality and security best practices.

## 🚀 Project Overview

This project simulates a small-scale election system where:
- **Voters** can register, log in, and cast exactly one vote.
- **Administrators** can view real-time results and reset elections.
- **Security** is prioritized through password hashing, session management, and transaction atomicity to prevent double-voting.

## 🏗️ Architecture

The application follows the **Model-View-Controller (MVC)** architectural pattern (implicitly provided by Flask):

1.  **Model (`models.py`)**: Defines the data structure (User, Candidate) using `SQLAlchemy`. It interacts with the SQLite database.
2.  **View (`templates/`)**: logic-less HTML files using `Jinja2` templating and `Bootstrap 5` for responsive design.
3.  **Controller (`app.py`)**: Handles incoming HTTP requests, processes business logic (authentication, vote recording), and renders the appropriate views.

### Key Technologies
- **Backend**: Python 3, Flask
- **Database**: SQLite (via Flask-SQLAlchemy)
- **Frontend**: HTML5, CSS3, Bootstrap 5
- **Authentication**: Flask-Login, Werkzeug Security

## 📂 File System Structure

```
VoteSecureLite/
│
├── app.py              # 🧠 Core Application Logic
│                       # Handles routing, authentication, and voting transactions.
│                       # Initializes the app and database.
│
├── models.py           # 💾 Database Models
│                       # Defines 'User' and 'Candidate' tables.
│                       # Contains helper methods for password hashing.
│
├── requirements.txt    # 📦 Dependencies
│                       # List of Python libraries required to run the app.
│
├── static/
│   └── style.css       # 🎨 Custom Styles
│                       # Supplementary CSS to improved UI/UX.
│
└── templates/          # 🖼️ HTML Templates
    ├── base.html       # internal parent template (navbar, footer, flash msgs)
    ├── index.html      # Landing page
    ├── login.html      # User login form
    ├── register.html   # User registration form
    ├── vote.html       # The Ballot (Radio buttons for candidates)
    ├── results.html    # Voting results (Table view)
    └── admin.html      # Admin dashboard (Reset controls)
```

## 🔒 Security Features (The "Secure" in VoteSecure)

1.  **Password Hashing**: Passwords are never stored in plain text. We use `werkzeug.security` to hash passwords before storing them in the database.
2.  **Session Management**: `Flask-Login` handles user sessions securely, preventing unauthorized access to the voting page.
3.  **One User, One Vote**: The `User` model tracks `has_voted` status. The backend checks this flag *before* committing a vote, ensuring fairness.
4.  **CSRF Protection (Implicit)**: While simple, the structure allows for easy addition of CSRF tokens (using Flask-WTF if expanded).
5.  **SQL Injection Prevention**: Using SQLAlchemy ORM automatically escapes values, protecting against injection attacks.

## 🛠️ Installation & Usage

### Prerequisites
- Python 3.x installed on your system.

### Steps

1.  **Navigate to the project directory**:
    ```bash
    cd VoteSecureLite
    ```

2.  **Install Dependencies**:
    It is recommended to use a virtual environment.
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the Application**:
    ```bash
    python app.py
    ```

4.  **Access the App**:
    Open your browser and go to `http://127.0.0.1:5000/`.

5.  **Demo Credentials**:
    - Register a new user to vote.
    - Register a user with username **admin** to access the Admin Dashboard (password can be anything you set).

## 📝 For Students & Developers

This code is written to be read. Check `app.py` for comments explaining the flow of data. Notice how `models.py` separates the data shape from the logic in `app.py`. This separation of concerns is critical in professional software development.

Happy Coding! 🚀

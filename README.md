
# 🎓 StudentSphere

<p align="center">
<strong>Your All-in-One Student Productivity Platform</strong>
</p>

<p align="center">
Helping students stay organized, productive, and focused through one modern platform.
</p>

---

## 🌟 About

StudentSphere is a modern student productivity platform built with **FastAPI**, **MongoDB**, and a lightweight frontend. It brings together essential academic tools such as authentication, document management, AI assistance, productivity utilities, and student-focused features in a single application.

## 💡 Why StudentSphere?

Students often juggle multiple apps for notes, documents, reminders, and study assistance. StudentSphere combines these capabilities into one platform to simplify academic workflows and improve productivity.

## ✨ Features

### 🔐 Authentication
- User registration & login
- JWT authentication
- Password hashing
- Protected routes

### 📂 File Management
- Upload study materials
- Manage documents

### 🤖 AI Assistant
- AI chatbot integration
- Academic assistance

### 📝 Productivity
- Sticky Notes
- To-do List
- Timer
- Stopwatch
- Digital Clock
- Motivational Quotes

### 🎵 Extras
- Spotify integration
- Responsive dashboard

---

## 🏗 Architecture

```text
Frontend (HTML/CSS/JS)
        │
     REST API
        │
FastAPI Backend
 ├── Authentication
 ├── AI Chatbot
 ├── File Upload
 └── User Management
        │
     MongoDB
```

---

## 🛠 Tech Stack

| Category | Technologies |
|----------|--------------|
| Frontend | HTML, CSS, JavaScript |
| Backend | Python, FastAPI, Uvicorn |
| Database | MongoDB, Motor |
| Authentication | JWT, Passlib |
| AI | OpenAI API / Gemini API |
| Tools | Git, GitHub, dotenv |

---

## 📂 Project Structure

```text
StudentSphere/
├── main.py
├── index.html
├── .env.example
├── .gitignore
├── __init__.py
└── README.md
```



---

## ⚙️ Installation

```bash
git clone https://github.com/itss-surya/StudentSphere.git
cd StudentSphere
```

Install dependencies:

```bash
pip install -r requirements.txt
```

If you don't have a `requirements.txt` yet, install the required packages manually:

```bash
pip install fastapi uvicorn motor pymongo python-jose passlib[bcrypt] python-multipart python-dotenv pydantic-settings
```

---

## 🌍 Environment Variables

Create a `.env` file:

```env
MONGODB_URL=your_mongodb_connection
JWT_SECRET_KEY=your_secret_key
OPENAI_API_KEY=your_api_key
AI_PROVIDER=fallback
```

---

## 🚀 Running the Project

Start MongoDB:

```bash
mongod
```

Run the backend:

```bash
uvicorn main:app --reload
```

Open:

- API: `http://localhost:8000`
- Swagger Docs: `http://localhost:8000/docs`

Open `index.html` in your browser to access the frontend.

---

## 💻 Usage

1. Register an account.
2. Log in securely.
3. Upload study materials.
4. Use the AI assistant.
5. Organize tasks with productivity tools.

---

## 🗺 Roadmap

- [x] Authentication
- [x] AI Chatbot
- [x] File Upload
- [x] Productivity Dashboard
- [ ] Calendar Integration
- [ ] Notifications
- [ ] Mobile Version
- [ ] Cloud Sync

---

## 🤝 Contributing

Contributions, suggestions, and bug reports are welcome. Feel free to fork the repository and open a pull request.

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

**Surya**

GitHub: https://github.com/itss-surya

---

⭐ If you found this project helpful, consider giving it a star!

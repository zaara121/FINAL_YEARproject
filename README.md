SmartStore DIEMS - MongoDB Version (Flask + MongoDB)

Quick start:
1. Install and run MongoDB locally (defaults to mongodb://localhost:27017).
2. Create and activate a Python virtual environment.
3. Install requirements:  pip install -r requirements.txt
4. Seed the database:    python seed_mongo.py
5. Run the app:          python app.py
6. Open http://127.0.0.1:5000 in your browser.

Default seeded users (from seed_mongo.py):
- admin / password  (role: admin)
- staff / password  (role: staff)

Passwords are initially stored as plaintext and converted to bcrypt hashes on first login.

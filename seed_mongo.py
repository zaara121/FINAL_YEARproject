from pymongo import MongoClient
from datetime import datetime

client = MongoClient("mongodb://localhost:27017/")
db = client["smartstore"]

# Clear old data (comment these if you don't want to drop)
db.users.delete_many({})
db.categories.delete_many({})
db.items.delete_many({})
db.transactions.delete_many({})

# Seed categories
categories = [
    {"name": "Computers"},
    {"name": "Mouse"},
    {"name": "Keyboards"},
    {"name": "CPU"},
]
cat_result = db.categories.insert_many(categories)
cat_ids = cat_result.inserted_ids

name_to_id = {
    "Computers": cat_ids[0],
    "Mouse": cat_ids[1],
    "Keyboards": cat_ids[2],
    "CPU": cat_ids[3],
}

# Seed items
items = [
    {"name": "DELL PC", "category_id": name_to_id["Computers"], "category_name": "Computers", "quantity": 45, "price": 89.99, "low_stock_threshold": 5},
    {"name": "DELL Mouse", "category_id": name_to_id["Mouse"], "category_name": "Mouse", "quantity": 5, "price": 34.50, "low_stock_threshold": 5},
    {"name": "LG keyboard", "category_id": name_to_id["Keyboards"], "category_name": "Keyboards", "quantity": 0, "price": 75.00, "low_stock_threshold": 3},
    {"name": "LG", "category_id": name_to_id["CPU"], "category_name": "CPU", "quantity": 120, "price": 12.99, "low_stock_threshold": 10},
    {"name": "DELL Mouse", "category_id": name_to_id["Mouse"], "category_name": "Mouse", "quantity": 15, "price": 8.50, "low_stock_threshold": 5},
    {"name": "LG PC", "category_id": name_to_id["Computers"], "category_name": "Computers", "quantity": 32, "price": 45.00, "low_stock_threshold": 5},
    {"name": "DELL keyboard", "category_id": name_to_id["Keyboards"], "category_name": "Keyboards", "quantity": 8, "price": 125.00, "low_stock_threshold": 5},
]
db.items.insert_many(items)

# Seed users (plaintext passwords; app will hash on first login)
users = [
    {"username": "admin", "password": "password", "role": "admin"},
    {"username": "staff", "password": "password", "role": "staff"},
]
db.users.insert_many(users)

print("MongoDB seeded successfully.")

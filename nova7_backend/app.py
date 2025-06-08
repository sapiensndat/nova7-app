import os
from dotenv import load_dotenv
import csv # Was in index.py, keep if used by other routes you might add back
from io import StringIO # Was in index.py
import uuid
from flask import Flask, request, jsonify, make_response
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, JSON, or_ # Ensure JSON and or_ are imported
from datetime import datetime, timedelta, timezone
from flask_cors import CORS
from flask_jwt_extended import (
    create_access_token, JWTManager, jwt_required, get_jwt_identity, decode_token
)
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError # Was in index.py
from flask_wtf.csrf import CSRFProtect, generate_csrf
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename # Was in index.py for uploads
# from google.cloud import storage # Uncomment if you integrate GCS for uploads in app.py
# import stripe # Uncomment if you integrate Stripe in app.py
import logging # Was in index.py

# Load .env file
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
dotenv_path = os.path.join(BASE_DIR, '.env')

if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
    print(f"Loaded .env file from: {dotenv_path}")
else:
    print(f"Warning: .env file not found at {dotenv_path}. Using environment variables or defaults.")

# Initialize Flask app
app = Flask(__name__) # Ensure app is named 'app' if that's what your WSGI server expects
ALLOWED_ORIGINS = [
    "http://127.0.0.1:5500", "http://127.0.0.1:5501",
    os.environ.get("FRONTEND_URL", "http://localhost:3000"),
    "https://nova7.vercel.app"
]
print(f"Allowed CORS origins: {ALLOWED_ORIGINS}")
CORS(app, supports_credentials=True, origins=ALLOWED_ORIGINS, methods=["GET", "HEAD", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"])


# CSRF Protection
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "a_very_strong_and_unique_csrf_secret_key_please_change_me") # Changed default
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

# JWT Configuration
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "another_very_strong_jwt_secret_key_please_change_me") # Changed default
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES_HOURS", 24)))
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_ERROR_MESSAGE_KEY"] = "message"

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL_INTERNAL', 'postgresql://nova7:Disaster2024@localhost:5432/nova7_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 465))
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'True').lower() in ('true', '1', 't')
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'False').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('nova7 App', os.environ.get('MAIL_DEFAULT_SENDER', os.environ.get('MAIL_USERNAME', 'noreply@example.com')))

jwt = JWTManager(app)
db = SQLAlchemy(app)
mail = Mail(app)

# CSRF Validation Decorator
def require_csrf_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE']:
            csrf_token_header = request.headers.get('X-CSRF-Token') # Corrected variable name
            if not csrf_token_header:
                return jsonify({"status": "error", "message": "CSRF token missing"}), 403
        return f(*args, **kwargs)
    return decorated

# --- Database Models ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    company_name = db.Column(db.String(150), nullable=True)
    business_name = db.Column(db.String(150), nullable=True)
    id_number = db.Column(db.String(50), nullable=True)
    id_document_url = db.Column(db.String(500), nullable=True)
    kyc_status = db.Column(db.String(20), default="pending", nullable=False)
    role = db.Column(db.String(50), default="user", nullable=False)
    profile_picture_url = db.Column(db.String(500), nullable=True)
    is_email_verified = db.Column(db.Boolean, default=False, nullable=False)
    email_verification_token = db.Column(db.String(100), nullable=True, unique=True)
    email_verification_token_expires = db.Column(db.DateTime, nullable=True)
    balance = db.Column(db.Float, default=0.0, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    transactions = db.relationship("Transaction", backref="user_transactions", lazy=True, cascade="all, delete-orphan") # Changed backref
    withdrawal_requests = db.relationship('WithdrawalRequest', backref='user_withdrawals', lazy=True, foreign_keys='WithdrawalRequest.user_id') # Changed backref
    lendable_products = db.relationship('LendableProduct', backref='product_owner_user', lazy=True, foreign_keys='LendableProduct.owner_id') # Changed backref
    marketplace_items = db.relationship("MarketplaceItem", backref="seller_user", lazy="dynamic", cascade="all, delete-orphan") # Added for MarketplaceItem.seller
    community_posts = db.relationship("CommunityPost", backref="author_user", lazy="dynamic", cascade="all, delete-orphan") # Added for CommunityPost.author
    comments = db.relationship("Comment", backref="commenter_user", lazy="dynamic", cascade="all, delete-orphan") # Added for Comment.commenter
    likes = db.relationship("Like", backref="liker_user", lazy="dynamic", cascade="all, delete-orphan") # Added for Like.liker

    def __repr__(self): return f"<User {self.full_name}>"

class Transaction(db.Model):
    __tablename__ = 'transaction'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False, default=lambda: datetime.now(timezone.utc).date())
    description = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {"id": self.id, "user_id": self.user_id, "type": self.type, "amount": self.amount, "category": self.category, 
                "date": self.date.strftime('%Y-%m-%d') if self.date else None, "description": self.description, 
                "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None}
    def __repr__(self): return f'<Transaction {self.id} {self.type} {self.amount}>'

class WithdrawalRequest(db.Model):
    __tablename__ = 'withdrawal_request'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='pending', nullable=False)
    request_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    processed_date = db.Column(db.DateTime, nullable=True)
    payment_details = db.Column(db.JSON, nullable=True)
    admin_notes = db.Column(db.Text, nullable=True)

class LendableProduct(db.Model):
    __tablename__ = 'lendable_product'
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(100), nullable=True)
    lending_terms = db.Column(db.Text, nullable=True)
    image_urls = db.Column(db.JSON, nullable=True)
    availability_status = db.Column(db.String(50), default='available', nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

# --- ADDING MarketplaceItem and CommunityPost related models ---
class MarketplaceItem(db.Model):
    __tablename__ = 'marketplace_item'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(100), nullable=True)
    price = db.Column(db.Float, nullable=False)
    condition = db.Column(db.String(50), nullable=True)
    image_urls = db.Column(db.JSON, nullable=True)
    location = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(50), default='active', nullable=False)
    is_service = db.Column(db.Boolean, default=False, nullable=False)
    quantity = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {"id": self.id, "user_id": self.user_id, 
                "seller_name": self.seller_user.full_name if self.seller_user else "N/A", # Uses backref from User
                "seller_email": self.seller_user.email if self.seller_user else None,
                "title": self.title, "description": self.description, "category": self.category, 
                "price": self.price, "condition": self.condition, "image_urls": self.image_urls or [], 
                "location": self.location, "status": self.status, "is_service": self.is_service, 
                "quantity": self.quantity, 
                "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
                "updated_at": self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else None}

class CommunityPost(db.Model):
    __tablename__ = 'community_post'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    comments = db.relationship('Comment', backref='parent_post', lazy='dynamic', cascade="all, delete-orphan")
    likes = db.relationship('Like', backref='liked_post', lazy='dynamic', cascade="all, delete-orphan")

    def to_dict(self, current_user_id_for_like_check=None):
        is_liked = False
        if current_user_id_for_like_check:
            is_liked = any(like.user_id == current_user_id_for_like_check for like in self.likes)
        return {"id": self.id, "user_id": self.user_id, 
                "author_name": self.author_user.full_name if self.author_user else "N/A", 
                "author_avatar_url": self.author_user.profile_picture_url if self.author_user and self.author_user.profile_picture_url else None,
                "content": self.content, "image_url": self.image_url, 
                "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
                "likes_count": self.likes.count(), "comments_count": self.comments.count(), 
                "is_liked_by_current_user": is_liked}

class Comment(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    post_id = db.Column(db.Integer, db.ForeignKey('community_post.id'), nullable=False, index=True)

class Like(db.Model):
    __tablename__ = 'like'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    post_id = db.Column(db.Integer, db.ForeignKey('community_post.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='uq_user_post_like'),)
# --- END OF ADDED MODELS ---


# CORS Preflight Response
def _build_cors_preflight_response():
    origin = request.headers.get('Origin')
    response = make_response()
    if origin in ALLOWED_ORIGINS:
        response.headers.add("Access-Control-Allow-Origin", origin)
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization,X-CSRF-Token")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS") # Ensure OPTIONS is here
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response

# Database Setup
@app.before_request
def initial_setup():
    if not hasattr(app, '_database_initialized_this_instance'):
        try:
            with app.app_context():
                db.create_all()
            print("Database tables checked/created.")
            app._database_initialized_this_instance = True
        except Exception as e:
            print(f"Error during initial table creation: {str(e)}")

# CSRF Token Endpoint
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token_route():
    token = generate_csrf()
    origin = request.headers.get('Origin')
    response = jsonify({"status": "success", "csrf_token": token})
    if origin in ALLOWED_ORIGINS:
         response.headers.add("Access-Control-Allow-Origin", origin)
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response, 200

# Basic Root Endpoint
@app.route('/')
def hello_world_route():
    return jsonify({"status": "success", "message": "nova7 Backend (app.py) is Running!"})

# --- Authentication Routes (existing, ensure JWT identity is handled as int after str conversion) ---
@app.route('/api/register', methods=['POST', 'OPTIONS'])
@require_csrf_token
def register_user_route():
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    data = request.get_json()
    if not data: return jsonify({"status": "error", "message": "Request body must be JSON"}), 400
    required_fields = ['fullName', 'email', 'password', 'businessName', 'idNumber']
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields: return jsonify({"status": "error", "message": f"Missing required fields: {', '.join(missing_fields)}"}), 400
    if User.query.filter_by(email=data['email']).first(): return jsonify({"status": "error", "message": "Email already registered"}), 409
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(
        full_name=data['fullName'], email=data['email'], password_hash=hashed_password,
        company_name=data.get('companyName'), business_name=data.get('businessName'),
        id_number=data.get('idNumber'), id_document_url=data.get('idDocumentUrl')
    )
    try:
        db.session.add(new_user)
        db.session.commit()
        print(f"User {new_user.id} registered: {new_user.email} with role '{new_user.role}', email verified: {new_user.is_email_verified}")
        return jsonify({"status": "success", "message": "User registered successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error registering user: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to register user due to a server error."}), 500

@app.route('/api/login', methods=['POST', 'OPTIONS'])
@require_csrf_token
def login_user_route():
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    data = request.get_json()
    if not data: return jsonify({"status": "error", "message": "Request body must be JSON"}), 400
    email = data.get('email')
    password = data.get('password')
    if not email or not password: return jsonify({"status": "error", "message": "Email and password are required"}), 400
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=str(user.id)) # Identity is string
        user_data = {
            "id": user.id, "fullName": user.full_name, "email": user.email,
            "balance": user.balance, "role": user.role,
            "isEmailVerified": user.is_email_verified, "companyName": user.company_name,
            "businessName": user.business_name, "profilePictureUrl": user.profile_picture_url
        }
        print(f"User {user.id} logged in: {user.email}")
        return jsonify({"status": "success", "message": "Login successful", "access_token": access_token, "user": user_data}), 200
    return jsonify({"status": "error", "message": "Invalid email or password"}), 401

# --- Dashboard Summary Route (existing, ensure JWT identity is handled as int) ---
@app.route('/api/dashboard/summary', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_dashboard_summary_route():
    if request.method == 'OPTIONS': return _build_cors_preflight_response()
    current_user_id_str = get_jwt_identity()
    try:
        current_user_id = int(current_user_id_str) # Convert string identity to int
    except ValueError:
        return jsonify(status="error", message="Invalid user ID format in token"), 400
        
    total_income = db.session.query(func.sum(Transaction.amount)).filter(Transaction.user_id == current_user_id, Transaction.type == 'income').scalar() or 0.0
    total_expenses = db.session.query(func.sum(Transaction.amount)).filter(Transaction.user_id == current_user_id, Transaction.type == 'expense').scalar() or 0.0
    net_balance = total_income - total_expenses
    profit_margin = ((net_balance) / total_income * 100) if total_income > 0 else 0.0
    summary_data = {"totalIncome": round(total_income, 2), "totalExpenses": round(total_expenses, 2), "netBalance": round(net_balance, 2), "profitMargin": round(profit_margin, 2), "overdueInvoicesAmount": 0.0, "overdueInvoicesCount": 0}
    return jsonify({"status": "success", "summary": summary_data}), 200

# --- ADDING Marketplace and Community Routes ---

@app.route('/api/marketplace/items', methods=['GET', 'OPTIONS'])
def get_marketplace_items_endpoint(): # Renamed to avoid conflict
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)
    search_term = request.args.get('search')
    category_filter = request.args.get('category')
    sort_by = request.args.get('sort', 'newest')
    
    query = MarketplaceItem.query.filter_by(status='active')
    if search_term:
        query = query.filter(or_(MarketplaceItem.title.ilike(f'%{search_term}%'), MarketplaceItem.description.ilike(f'%{search_term}%')))
    if category_filter:
        query = query.filter_by(category=category_filter)
    if sort_by == 'price_low_high':
        query = query.order_by(MarketplaceItem.price.asc())
    elif sort_by == 'price_high_low':
        query = query.order_by(MarketplaceItem.price.desc())
    else:
        query = query.order_by(MarketplaceItem.created_at.desc())
        
    try:
        paginated_items = query.paginate(page=page, per_page=per_page, error_out=False)
        items_list = [item.to_dict() for item in paginated_items.items]
        return jsonify({"status": "success", "items": items_list, "total_items": paginated_items.total,
                        "total_pages": paginated_items.pages, "current_page": paginated_items.page,
                        "has_next": paginated_items.has_next, "has_prev": paginated_items.has_prev}), 200
    except Exception as e:
        print(f"Error fetching marketplace items: {str(e)}")
        return jsonify({"status": "error", "message": "Could not retrieve marketplace items."}), 500

@app.route('/api/community/posts', methods=['GET', 'POST', 'OPTIONS'])
@jwt_required() 
@require_csrf_token # For POST
def community_posts_endpoint(): # Renamed
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()

    current_user_id_str = get_jwt_identity()
    try:
        current_user_id = int(current_user_id_str) # Convert string identity to int
    except ValueError:
        return jsonify(status="error", message="Invalid user ID format in token"), 400

    if request.method == 'GET':
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        try:
            paginated_posts = CommunityPost.query.order_by(CommunityPost.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
            # Pass current_user_id to to_dict for like status
            posts_list = [post.to_dict(current_user_id_for_like_check=current_user_id) for post in paginated_posts.items]
            return jsonify({"status": "success", "posts": posts_list,
                            "total_posts": paginated_posts.total, "total_pages": paginated_posts.pages,
                            "current_page": paginated_posts.page, "has_next": paginated_posts.has_next,
                            "has_prev": paginated_posts.has_prev}), 200
        except Exception as e:
            print(f"Error fetching community posts: {str(e)}")
            return jsonify({"status": "error", "message": "Could not retrieve community posts."}), 500

    elif request.method == 'POST':
        data = request.get_json()
        if not data or not data.get('content'):
            return jsonify({"status": "error", "message": "Post content is required"}), 400
        
        content = data.get('content')
        image_url = data.get('imageUrl')
        new_post = CommunityPost(user_id=current_user_id, content=content, image_url=image_url)
        try:
            db.session.add(new_post)
            db.session.commit()
            return jsonify({"status": "success", "message": "Post created successfully!", 
                            "post": new_post.to_dict(current_user_id_for_like_check=current_user_id)}), 201
        except Exception as e:
            db.session.rollback()
            print(f"Error creating community post: {str(e)}")
            return jsonify({"status": "error", "message": "Failed to create post."}), 500

# --- END OF ADDED ROUTES ---

# (Other routes like withdrawals, lending products, etc., are already present)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5005))
    app.run(debug=True, host='0.0.0.0', port=port) # Added host='0.0.0.0' for broader accessibility
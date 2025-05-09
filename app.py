from flask import Flask, render_template, request, redirect, session, flash
from flask_pymongo import PyMongo
import bcrypt, pyotp, jwt, datetime
from bson.objectid import ObjectId

app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config["MONGO_URI"] = "mongodb://localhost:27017/allusers"
mongo = PyMongo(app)
users_collection = mongo.db.users

JWT_SECRET = "jwt_secret_key"

@app.route('/')
def index():
    return redirect('/signup')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if users_collection.find_one({'$or': [{'username': username}, {'email': email}]}):
            flash('User already exists. Please login.')
            return redirect('/login')
        
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        totp_secret = pyotp.random_base32()
        
        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': hashed_pw,
            'totp': totp_secret
        })
        
        flash(f'Signup successful! Add this key to Google Authenticator: {totp_secret}')
        return redirect('/login')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        token = request.form['token']
        
        user = users_collection.find_one({'username': username})
        if not user:
            flash('Invalid username or password')
            return redirect('/login')
        
        if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            flash('Invalid username or password')
            return redirect('/login')
        
        totp = pyotp.TOTP(user['totp'])
        if not totp.verify(token):
            flash('Invalid 2FA token')
            return redirect('/login')
        
        jwt_token = jwt.encode(
            {'user_id': str(user['_id']), 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            JWT_SECRET,
            algorithm="HS256"
        )
        session['jwt'] = jwt_token
        session['username'] = user['username']
        return redirect('/home')
    
    return render_template('login.html')

@app.route('/home')
def home():
    if 'jwt' not in session:
        return redirect('/login')
    try:
        jwt.decode(session['jwt'], JWT_SECRET, algorithms=["HS256"])
        return render_template('home.html', username=session['username'])
    except jwt.ExpiredSignatureError:
        flash("Session expired. Please log in again.")
        return redirect('/login')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)

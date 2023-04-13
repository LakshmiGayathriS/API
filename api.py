from flask import Flask, render_template, url_for, redirect, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import psycopg2
import psycopg2.extras
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
import jwt
from datetime import timedelta
from dotenv import load_dotenv
import os

load_dotenv()
url = os.getenv('url')
secret_key = os.getenv('secret_key')
jwt_key = os.getenv('jwt_key')

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = url
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secret_key
app.config['JWT_SECRET_KEY'] = jwt_key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)

db = SQLAlchemy(app)
jwt = JWTManager(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(50), nullable=False)

with app.app_context():
    db.create_all()



@app.route("/login", methods = ['POST'])
def login():

    username = request.json['username']
    password = request.json['password']

    user = User.query.filter_by(username=username).first()
    if user:
        print(user)
        if bcrypt.check_password_hash(user.password, password):
            login_user(user)
            access_token = create_access_token(identity=user.id)
            
            return jsonify({'message': 'Login successful','access_token': access_token})
            
            
    return jsonify({'message':'Login failed'})


@app.route("/register", methods = ['POST'])
def register():

    username = request.json['username']
    password = request.json['password']

    existing_username = User.query.filter_by(username=username).first()

    if existing_username:
        return jsonify({'message':'username already exists'})

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message':'Register successful'})

@app.route("/update", methods=["PATCH"])
@login_required
def update_user():
    user_id = request.json['username']
    new_password = request.json['password']
    
    user = User.query.filter_by(username=user_id).first()
    if not user:
        return jsonify({'message': 'User not found'})
    
    hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")
    
    user.password = hashed_password
    db.session.commit()
    return jsonify({'message': 'Password updated successfully'})

@app.route("/delete", methods=["DELETE"])
@login_required
def delete_user():
    user_id = request.json['username']
    
    user = User.query.filter_by(username=user_id).first()
    if not user:
        return jsonify({'message': 'User not found'})
    
    db.session.delete(user)
    db.session.commit()
    logout_user()
    return jsonify({'message': 'User deleted successfully'})



@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    
    return jsonify ({'message':'token success'})

if __name__ == "__main__":
    app.run(debug = True)
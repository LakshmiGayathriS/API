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
from datetime import timedelta



app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Gayathri$25@localhost/mydatasignup'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secretkey'
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
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
            return jsonify({'access_token': access_token})
            # return jsonify({'message':'Login successful'})
            
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

if __name__ == "__main__":
    app.run(debug = True)
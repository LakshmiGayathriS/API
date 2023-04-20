from flask import Flask, render_template, url_for, redirect, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import psycopg2
import psycopg2.extras
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_current_user
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

Roles_dict = { 1 : 'admin', 2 : 'manager', 3 : 'employee'}

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    manager_id = db.Column(db.Integer, nullable=True)
    role_id = db.Column(db.Integer, nullable=False)
    # manager = db.relationship('manager', backref = 'users', lazy=True)
    # role = db.relationship('roles', backref = 'users', lazy=True)

class Manager(db.Model, UserMixin):
    manager_id = db.Column(db.Integer, primary_key=True)
    manager_name = db.Column(db.String(20), nullable=False)


with app.app_context():
    db.create_all()

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        password = '12345678'
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username='admin', password=hashed_password, role_id=1)
        db.session.add(new_user)
        db.session.commit()


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


@app.route("/add_emp",methods = ['POST'])
@jwt_required()
def add_emp():
    # print("hi")
    user_id = get_jwt_identity()
    user_detail = User.query.filter_by(id=user_id).first()

    if Roles_dict[user_detail.role_id] == 'admin':
        username = request.json['username']
        password = request.json['password']
        manager_id = request.json['manager_id']
        role_id = request.json['role_id']
        manager_name = request.json.get('manager_name')

        if Roles_dict[role_id] == 'manager':
            new_manager = Manager(manager_id=manager_id,manager_name=manager_name)
            db.session.add(new_manager)
            db.session.commit()
            return ({'message':'manager created successfully'})

        no_manager = Manager.query.filter_by(manager_id=manager_id).first()
        if not no_manager:
            return jsonify({'message':'No such manager'})

        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            return jsonify({'message':'username already exists'})

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, password=hashed_password,manager_id=manager_id,role_id=role_id)
        db.session.add(new_user)
        db.session.commit()

        return jsonify ({'message':'employee added successfully'})

    return jsonify ({'No access. Only admin can add employees'})

@app.route("/change_manager",methods = ['PATCH'])
@jwt_required()
def change_manager():
    user_id = get_jwt_identity()
    user_detail = User.query.filter_by(id=user_id).first()

    if Roles_dict[user_detail.role_id] == 'admin':
        username = request.json['username']
        manager_id = request.json['manager_id']

        no_manager = Manager.query.filter_by(manager_id=manager_id).first()
        if not no_manager:
            return jsonify({'message':'No such manager'})

        existing_username = User.query.filter_by(username=username).first()
        if not existing_username:
            return jsonify({'message':'username does not exists'})

        existing_username.manager_id = manager_id
        db.session.commit()
        return jsonify({'message':'Manager changed successfully'})


@app.route("/show_details/<int:user_id>",methods = ['POST'])
@jwt_required()
def show_details(user_id):
    user_id = get_jwt_identity()
    user_detail = User.query.filter_by(id=user_id).first()
    user_req = User.query.filter_by(id=user_id).first()
    reportees_details = []

    if Roles[user_detail.role_id]:
        reportees_details.append({
            "username":user_req.username,
            "role":Roles[user_req.role_id]
        })

    if Roles[user_detail.role_id] not 'employee':
        if Roles[user_req.role_id] == 'manager':
            managers = User.query.filter_by(manager_id=user_req.role_id).all()
            
            for manager in managers:
                reportees_datails.append({
                "reportee":manager.username
                })
            return jsonify({reportees_datails})

        if Roles[user_req.role_id] == 'employee':
            reporting_to = Manager.query.filter_by(manager_id=User.query.filter_by(role_id=user_req.role_id).first().manager_id).first()
            reportees_datails.append({
                "reporting to ": reporting_to
                })
            return jsonify({reportees_datails})



# @app.route("/promote_demote",methods = ['PATCH'])
# @jwt_required()
# def promote_demote():
#     user_id = get_jwt_identity()
#     user_detail = User.query.filter_by(id=user_id).first()

#     if Roles_dict[user_detail.role_id] == 'admin':
#         action = request.json['action']
#         username = request.json['username']
        
#         if action == 'promote':
            

# @app.route("/register", methods = ['POST'])
# def register():

#     username = request.json['username']
#     password = request.json['password']
#     manager_id = request.json.get('manager_id', None)
#     role_id = request.json['role_id']

#     existing_username = User.query.filter_by(username=username).first()
#     if existing_username:
#         return jsonify({'message':'username already exists'})

#     hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
#     new_user = User(username=username, password=hashed_password,role_id=role_id)
#     db.session.add(new_user)
#     db.session.commit()

#     return jsonify({'message':'Register successful'})

@app.route("/update", methods=["PATCH"])
@jwt_required()
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
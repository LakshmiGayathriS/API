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
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    role_id = db.Column(db.Integer, nullable=False)
    subordinates = db.relationship('User', backref=db.backref('manager', remote_side=[id]))

    # manager = db.relationship('manager', backref = 'users', lazy=True)
    # role = db.relationship('roles', backref = 'users', lazy=True)

# class Manager(db.Model, UserMixin):
#     manager_id = db.Column(db.Integer, primary_key=True)
#     manager_name = db.Column(db.String(20), nullable=False)


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
        manager_id = request.json.get('manager_id',None)
        role_id = request.json['role_id']
        # manager_name = request.json.get('manager_name')
        
        no_manager = User.query.filter_by(id=manager_id).first()
        if no_manager and Roles_dict[no_manager.role_id] != 'manager':
            return jsonify({'message':'No such manager'})

        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            return jsonify({'message':'username already exists'})

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, password=hashed_password,manager_id=manager_id,role_id=role_id)
        db.session.add(new_user)
        db.session.commit()
        
        # if Roles_dict[role_id] == 'manager':
        #     existing_username = User.query.filter_by(username=username).first()
        #     new_manager = Manager(manager_id=existing_username.id,manager_name=existing_username.username)
        #     db.session.add(new_manager)
        #     db.session.commit()

        return jsonify ({'message':'employee added successfully'})

    return jsonify ({'message':'Admin access only'})

@app.route("/change_manager",methods = ['PATCH'])
@jwt_required()
def change_manager():
    user_id = get_jwt_identity()
    user_detail = User.query.filter_by(id=user_id).first()

    if Roles_dict[user_detail.role_id] == 'admin':
        username = request.json['username']
        manager_id = request.json['manager_id']

        no_manager = User.query.filter_by(id=manager_id).first()
        if Roles_dict[no_manager.role_id] != 'manager':
            return jsonify({'message':'No such manager'})

        existing_username = User.query.filter_by(username=username).first()
        if not existing_username:
            return jsonify({'message':'username does not exists'})

        existing_username.manager_id = manager_id
        db.session.commit()
        return jsonify({'message':'Manager changed successfully'})

    return jsonify ({'message':'Admin access only'})

@app.route("/show_details/<int:user_no>",methods = ['POST'])
@jwt_required()
def show_details(user_no):
    user_id = get_jwt_identity()
    user_detail = User.query.filter_by(id=user_id).first()
    user_req = User.query.filter_by(id=user_no).first()
    reportees_details = {}
    reportees_det = []

    if Roles_dict[user_detail.role_id]:
        reportees_details['user'] = {
            "username":user_req.username,
            "role":Roles_dict[user_req.role_id]
        }

    if Roles_dict[user_detail.role_id] != 'employee':
        if Roles_dict[user_req.role_id] == 'manager':
            managers = User.subordinates
            for manager in managers:
                user_name={}
                user_name['username'] = manager.username 
                user_name['role'] = Roles_dict[manager.role_id]       
                reportees_det.append(user_name)
            return jsonify(reportees_details, reportees_det)

        if Roles_dict[user_req.role_id] == 'employee':
            reporting_to = User.query.filter_by(id=user_req.manager_id).first()
            reportees_details['manager'] = {
                "reporting to ": reporting_to.username
            }
            return jsonify(reportees_details)

    return jsonify(reportees_details)

# @app.route("/show_details/<int:user_id>",methods = ['POST'])
# @jwt_required()
# def show_details(user_id):
#     user_id = get_jwt_identity()
#     user_detail = User.query.filter_by(id=user_id).first()
#     user_req = User.query.filter_by(id=user_id).first()
#     reportees_details = []

#     if Roles_dict[user_detail.role_id]:
#         reportees_details.append({
#             "username":user_req.username,
#             "role":Roles_dict[user_req.role_id]
#         })

#     if Roles_dict[user_detail.role_id] != 'employee':
#         if Roles_dict[user_req.role_id] == 'manager':
#             managers = User.query.filter_by(manager_id=user_req.id).all()
#             for manager in managers:
#                 reportees_details.append({
#                 "reportee":manager.username
#                 })
#             return jsonify({reportees_details})

#         if Roles_dict[user_req.role_id] == 'employee':
#             reporting_to = User.query.filter_by(id=user_req.manager_id).first()
#             reportees_details.append({
#                 "reporting to ": reporting_to.username
#                 })
#             return jsonify({reportees_details})
#     return jsonify({reportees_details})


@app.route("/promote_demote",methods = ['PATCH'])
@jwt_required()
def promote_demote():
    user_id = get_jwt_identity()
    user_detail = User.query.filter_by(id=user_id).first()

    if Roles_dict[user_detail.role_id] == 'admin':
        action = request.json['action']
        username = request.json['username']
        user_act = User.query.filter_by(username=username).first()
        
        if action == 'promote':
            user_act.role_id = 2
            db.session.commit()
            return jsonify({'message':'employee promoted'})

        else:
            user_act.role_id = 3
            remove_managers = User.query.filter_by(manager_id=user_act.id).all()
            if remove_managers:
                for remove_manager in remove_managers:
                    remove_manager.manager_id = None
                    db.session.commit()
            db.session.commit()
            return jsonify({'message':'employee demoted'})

    return jsonify ({'message':'Admin access only'})


@app.route("/role_details",methods = ['POST'])
def role_details():
    role_id = request.json['role_id']

    if role_id:
        users = User.query.filter_by(role_id=role_id).all()
        role_det = []
        for user in users:
            user_name={}
            user_name['username'] = user.username 
            user_name['id'] = user.id     
            role_det.append(user_name)
        return jsonify(role_det)

    return jsonify({'message':'Incorrect role id'})


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
    user_id = get_jwt_identity()
    user_detail = User.query.filter_by(id=user_id).first()
    
    username = request.json['username']
    new_password = request.json['password']

    if user_detail.username == username:
    
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'message': 'User not found'})
        
        hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")
        
        user.password = hashed_password
        db.session.commit()
        return jsonify({'message': 'Password updated successfully'})
    
    return jsonify({'message':'No access'})


@app.route("/delete", methods=["DELETE"])
@jwt_required()
def delete_user():
    user_id = get_jwt_identity()
    user_detail = User.query.filter_by(id=user_id).first()

    if Roles_dict[user_detail.role_id] == 'admin':
        user_id = request.json['username']
        user = User.query.filter_by(username=user_id).first()
        if not user:
            return jsonify({'message': 'User not found'})
        if Roles_dict[user.role_id] == 'manager':
            remove_managers = User.query.filter_by(manager_id=user.id).all()
            if remove_managers:
                for remove_manager in remove_managers:
                    remove_manager.manager_id = None
                    db.session.commit()
                db.session.commit()
        db.session.delete(user)
        db.session.commit()
        logout_user()
        return jsonify({'message': 'User deleted successfully'})

    return jsonify({'message':'Admin access only'})



@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    
    return jsonify ({'message':'token success'})



if __name__ == "__main__":
    app.run(debug = True)

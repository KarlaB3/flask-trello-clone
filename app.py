from flask import Flask, jsonify, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow.validate import Length
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta, date

app = Flask(__name__)
ma = Marshmallow(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql+psycopg2://db_dev:123456@localhost:5432/trello_clone_db"
db = SQLAlchemy (app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
app.config ["JWT_SECRET_KEY"] = "Backend best end"

class Card(db.Model):
    __tablename__= "CARDS"
    id = db.Column(db.Integer,primary_key=True)
    title = db.Column(db.String())
    description = db.Column(db.String())
    date = db.Column(db.Date())
    status = db.Column(db.String())
    priority = db.Column(db.String())

class CardSchema(ma.Schema):
    class Meta:
        fields = ("id", "title", "description","date","status","priority")

card_schema = CardSchema()
cards_schema = CardSchema(many=True)

@app.cli.command("create")
def create_db():
    db.create_all()
    print("Tables created")

@app.cli.command("seed")
def seed_db():
    from datetime import date
    card1 = Card(
        title = "Start the project",
        description = "Stage 1, creating the database",
        status = "To Do",
        priority = "High",
        date = date.today()
    )

    db.session.add(card1)

    card2 = Card(
        title = "SQLAlchemy and Marshmallow",
        description = "Stage 2, integrate both modules in the project",
        status = "Ongoing",
        priority = "High",
        date = date.today()
    )

    db.session.add(card2)

    admin_user = User(
        email = "admin",
        password = bcrypt.generate_password_hash("password123").decode("utf-8"),
        admin = True
    )
    
    db.session.add (admin_user)

    user1 = User(
        email = "user1",
        password = bcrypt.generate_password_hash("123456").decode("utf-8")
    )

    db.session.add(user1)

    db.session.commit()
    print("Table seeded")

@app.cli.command("drop")
def drop_db():
    db.drop_all()
    print("Tables dropped") 

class User(db.Model):
    __tablename__ = "USERS"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(), nullable=False, unique=True)
    password = db.Column(db.String(), nullable=False)
    admin = db.Column(db.Boolean(), default=False)

class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
    password = ma.String(validate=Length(min=6))

user_schema = UserSchema()
users_schema = UserSchema(many=True)

@app.route("/")
def hello():
    return "<p>Hello, World!</p>"

@app.route("/cards", methods=["GET"])
def get_cards():
    cards_list = Card.query.all()
    result = cards_schema.dump(cards_list)
    return jsonify(result)

@app.route("/cards", methods=["POST"])
#Decorator to make sure the jwt is included in the request
@jwt_required()
def card_create():
    #Create a new card
    card_fields = card_schema.load(request.json)

    new_card = Card()
    new_card.title = card_fields["title"]
    new_card.description = card_fields["description"]
    new_card.status = card_fields["status"]
    new_card.priority = card_fields["priority"]
    new_card.date = date.today()
    db.session.add(new_card)
    db.session.commit()
    return jsonify(card_schema.dump(new_card))

@app.route("/cards/<int:id>", methods=["DELETE"])
@jwt_required()
def card_delete(id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return abort(401, description="Invalid user")
    if not user.admin:
        return abort(401, description="Unathorised user")
    
    card = Card.query.filter_by(id=id).first()
    if not Card:
        return abort(400, description="Card doesn't exist")
    db.session.delete(card)
    db.session.commit()
    return jsonify(card_schema.dump(card))

@app.route("/auth/register", methods=["POST"])
def auth_register():
    user_fields = user_schema.load(request.json)
    user = User.query.filter_by(email=user_fields["email"]).first()
    if user:
        return abort (400, description="Email already registered.")
    user = User()
    user.email = user_fields["email"]
    user.password = bcrypt.generate_password_hash(user_fields["password"]).decode("utf-8")
    user.admin = False
    db.session.add(user)
    db.session.commit()
    expiry = timedelta(days=1)
    access_token = create_access_token(identity=str(user.id), expires_delta=expiry)
    return jsonify({"user":user.email, "token": access_token})

@app.route("/auth/login", methods=["POST"])
def auth_login():
    user_fields = user_schema.load(request.json)
    user = User.query.filter_by(email=user_fields["email"]).first()
    if not user or not bcrypt.check_password_hash(user.password, user_fields["password"]):
        return abort(401, description="Incorrect username and password.")
    expiry = timedelta(days=1)
    access_token = create_access_token(identity=str(user.id), expires_delta=expiry)
    return jsonify({"user":user.email, "token": access_token})
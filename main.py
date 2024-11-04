from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CREATE DATABASE


class Base(DeclarativeBase):
    pass

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CREATE TABLE IN DB
# Define User model with UserMixin. Our user have 3 extra features with UserMixin: is_active,
# is_authenticated, is_anonymous

class User(UserMixin,db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=False)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))



with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        email=request.form.get('email')
        result = db.session.execute(db.select(User).where(User.email == email))
        user_data = result.scalar()
        if user_data:
            flash('You have already signed up. Please login instead')
            return redirect(url_for('login'))

        hash_and_salted_password= generate_password_hash(
                                   request.form.get('password'),
                                   method='pbkdf2:sha256',
                                   salt_length=8        )

        user=User( email=request.form.get('email'),
                   name=request.form.get('name'),
                   password=hash_and_salted_password )
        db.session.add(user)
        db.session.commit()
        # Log in and authenticate user after adding details to database
        login_user(user)
        # Can redirect() and get name from the current_user
        return redirect(url_for('secrets'))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST','GET'])
def login():
    if request.method=='POST':
        email=request.form.get('email')
        password=request.form.get('password')

        #find user in database by email
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        # Check stored password hash against entered password hashed
        if not user:
            flash(message='not a valid user. Please try again')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash(message='Incorrect Password. Please try again')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))

    return render_template("login.html", logged_in=current_user.is_authenticated)



@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name,logged_in=True )


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/download', methods=['GET','POST'])
@login_required
def download():
    if request.method=='GET':
        return send_from_directory('static', path="files/cheat_sheet.pdf")



if __name__ == "__main__":
    app.run(debug=True)

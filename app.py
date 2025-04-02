from flask import Flask, render_template, redirect, url_for, flash, request,session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
# bcrypt = Bcrypt(app)
# login_manager = LoginManager(app)
# login_manager.login_view = 'login'

# # User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password= db.Column(db.String(150), nullable=False)
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password, password)    

# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))

# # Registration Form
# class RegisterForm(FlaskForm):
#     username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
#     password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=20)])
#     confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
#     submit = SubmitField('Register')

# # Login Form
# class LoginForm(FlaskForm):
#     username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
#     password = PasswordField('Password', validators=[InputRequired()])
#     submit = SubmitField('Login')

# # Routes
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if user:
        if user.check_password(password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return "render_template('index.html')"

@app.route('/register', methods=['GET', 'POST'])
def register():
    username=request.form.get('username')
    password=request.form.get('password')
    user=User.query.filter_by(username=username).first()
    if user:
        return "render_template('index.html')"
    
    new_user=User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    session['username']=username
    return redirect(url_for('dashboard'))




@app.route('/')
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))
    
    return render_template('index.html')

@app.route('/dashboard')

def dashboard():
    if "username" in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('home'))
    

# @app.route('/logout')
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('login'))

    

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)

from flask import Flask , render_template , url_for , request , redirect,flash,session
from flask_sqlalchemy import SQLAlchemy

from werkzeug.security import generate_password_hash , check_password_hash

app=Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///users.db'
app.secret_key='secret_key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db=SQLAlchemy(app)

class User(db.Model):
        id=db.Column(db.Integer,primary_key=True)
        name=db.Column(db.String(100))
        email=db.Column(db.String(50),unique=True)
        password=db.Column(db.String(100))
with app.app_context():
        db.create_all()


@app.route('/')
def home():
        return render_template('home.html') 
@app.route('/login',methods=['GET','POST'])    #login page
def login():
        if request.method=='POST':
                email=request.form['email']
                password=request.form['password']
                user=User.query.filter_by(email=email).first()
                if user and check_password_hash(user.password,password):
                        session['user_id']=user.id
                        session['user_name']=user.name
                        flash('Signin successful','success')
                        return redirect(url_for('home'))
        return render_template('login.html')


@app.route('/signup',methods=['GET','POST'])    #register page
def signup():
        if request.method=='POST':
                name=request.form['name']
                email=request.form['email']
                password=request.form['password']
                confirm_password=request.form['confirm_password']

                if not name or len(name.strip())<2:
                        flash('name must be atleast 2 character long','error')
                        return redirect(url_for('signup'))
                if not email or '@' not in email :
                        flash('Invalid email','error')
                        return redirect(url_for('signup'))
                if not password or len(password)<8 or not any(char.isalpha() for char in password ) or not any(char.isdigit() for char in password) or not any (not char.isalnum() for char in password):
                        flash('pass must be atleast 8 char long and contain letters and contain numbers and special characters','error')
                        return redirect(url_for('signup'))
                if confirm_password!=password:
                        flash('Confirm password should match password','error')
                        return redirect(url_for('signup'))
                #check if user already exists
                existing_user=User.query.filter_by(email=email).first()
                if existing_user:
                        flash('Email already exists.Please login. ','error')
                        return redirect(url_for('signup'))
                # generate hash password
                hashed_password=generate_password_hash(password)
                new_user=User(
                        name=name.strip(),
                        email=email.strip(),
                        password=hashed_password
                )
                try:
                        db.session.add(new_user)
                        db.session.commit()
                        flash('Registration successful .Proceed to signin','success')
                        return redirect(url_for('signin'))
                except Exception as e:
                        db.session.rollback()
                        flash('Some error occured while registering','error')
                        return redirect(url_for('signup'))

        return render_template('signup.html')


if __name__=='__main__':
        app.run(debug=True )
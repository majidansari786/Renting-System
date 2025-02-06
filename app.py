from flask import Flask, render_template, request, redirect, url_for, session, flash, render_template
from markupsafe import Markup
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rent.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    username = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(100))
    
    def __init__(self,password,username):
        self.username = username
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))
    
    def get_id(self):
        return self.username 

class Tenant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_name = db.Column(db.String(255), nullable=False)
    mobile_no = db.Column(db.String(15), nullable=False, unique=True)
    aadhar_no = db.Column(db.String(12), nullable=False, unique=True)
    date_of_joining = db.Column(db.Date, nullable=False)
    father_name = db.Column(db.String(255))
    mother_name = db.Column(db.String(255))
    address = db.Column(db.Text)
    room_no = db.Column(db.String(100), nullable=False, unique=False)

    # Relationship to RentPayment
    rent_payments = db.relationship('RentPayment', backref='tenant', lazy=True)

class RentPayment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    amount_paid = db.Column(db.Float, nullable=False)
    payment_date = db.Column(db.Date, nullable=False)
    payment_mode = db.Column(db.String(50), nullable=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(username):
    return User.query.get(username)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login' , methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return "Please fill in all fields", 400
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin'))
        
        # If the user doesn't exist or password doesn't match
        flash('Invalid username or password')

    return render_template('login.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('add_tenant'))
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash('user sucessfully created', 'success')
        return redirect('/')
    return render_template('register.html')

@app.route('/add_tenant', methods=['GET', 'POST'])
@login_required
def add_tenant():
    if request.method == 'POST':
        tenant_name = request.form['tenant_name']
        mobile_no = request.form['mobile_no']
        aadhar_no = request.form['aadhar_no']
        date_of_joining = datetime.strptime(request.form['date_of_joining'], '%Y-%m-%d').date()  # Convert string to date
        father_name = request.form['father_name']
        mother_name = request.form['mother_name']
        address = request.form['address']
        room_no = request.form['room_no']
        tenant = Tenant(tenant_name=tenant_name, mobile_no=mobile_no, aadhar_no=aadhar_no, date_of_joining=date_of_joining, father_name=father_name, mother_name=mother_name, address=address, room_no=room_no)
        db.session.add(tenant)
        db.session.commit()
        flash('Tenant added successfully', 'success')
        return redirect('/admin')
    return render_template('add_tenant.html')

@app.route('/admin')
@login_required
def admin():
    tenants = Tenant.query.filter_by().all()
    return render_template('admin.html', tenants=tenants)

@app.route('/tenant/<tenant_name>', methods=['GET', 'POST'])
@login_required
def tenant_detail(tenant_name):
    tenant = Tenant.query.filter(Tenant.tenant_name.ilike(tenant_name)).first()
    if tenant:
        return render_template('tenant_detail.html', tenant=tenant)
    return "Tenant not found", 404

@app.route('/rent/<tenant_name>', methods=['GET', 'POST'])
@login_required
def rent(tenant_name):
    # Retrieve the tenant by name
    tenant = Tenant.query.filter(Tenant.tenant_name.ilike(tenant_name)).first()

    if not tenant:
        flash("Tenant not found.", "danger")
        return redirect(url_for('admin'))  # Redirect to admin or any other appropriate page

    if request.method == 'POST':
        try:
            payment_date = datetime.strptime(request.form['payment_date'], '%Y-%m-%d').date()
            amount_paid = float(request.form['amount_paid'])  # Ensure it's a valid float
            payment_mode = request.form['payment_mode']

            if amount_paid <= 0:
                flash("Amount paid should be greater than zero.", "danger")
                return redirect(url_for('rent', tenant_name=tenant_name))

            # Create rent payment with tenant association
            rent = RentPayment(
                payment_mode=payment_mode,
                amount_paid=amount_paid,
                payment_date=payment_date,
                tenant_id=tenant.id  # Use tenant.id instead of tenant_name
            )
            db.session.add(rent)
            db.session.commit()
            flash('Rent added successfully', 'success')
            return redirect(url_for('rent', tenant_name=tenant_name))

        except ValueError:
            flash("Invalid input for payment amount. Please enter a valid number.", "danger")
            return redirect(url_for('rent', tenant_name=tenant_name))

    return render_template('rent.html', tenant=tenant)  # Pass tenant object to template



if __name__ == '__main__':
    app.run(debug=True)

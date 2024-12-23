from flask import Flask, flash, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_bcrypt import Bcrypt

# Configuración de la aplicación
app = Flask(__name__)
app.config["SECRET_KEY"] = '65b0b774279de460f1cc5c92'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///ums.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = 'filesystem'

# Inicialización de extensiones
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)

# Modelos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(255), nullable=False)
    lname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    edu = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)

    def __repr__(self):
        return f'User("{self.id}", "{self.fname}", "{self.lname}", "{self.email}", "{self.edu}", "{self.username}", "{self.status}")'


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'Admin("{self.username}", "{self.id}")'

# Crear tablas y datos iniciales
with app.app_context():
    db.create_all()

    # Insertar un administrador inicial si no existe
    if not Admin.query.filter_by(username='hilal123').first():
        admin = Admin(username='hilal123', password=bcrypt.generate_password_hash('hilal123', 10))
        db.session.add(admin)
        db.session.commit()
        print("Administrador inicial creado.")

# Rutas principales
@app.route('/')
def index():
    return render_template('index.html', title="Inicio")


# ------------------------- Área de Administración -------------------------

@app.route('/admin/', methods=["POST", "GET"])
def adminIndex():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Por favor, completa todos los campos.', 'danger')
            return redirect('/admin/')

        admin = Admin.query.filter_by(username=username).first()
        if admin and bcrypt.check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            session['admin_name'] = admin.username
            flash('Inicio de sesión exitoso.', 'success')
            return redirect('/admin/dashboard')
        else:
            flash('Usuario o contraseña inválidos.', 'danger')
            return redirect('/admin/')
    return render_template('admin/index.html', title="Login de Admin")


@app.route('/admin/dashboard')
def adminDashboard():
    if not session.get('admin_id'):
        return redirect('/admin/')
    totalUser = User.query.count()
    totalApprove = User.query.filter_by(status=1).count()
    NotTotalApprove = User.query.filter_by(status=0).count()
    return render_template('admin/dashboard.html', title="Panel de Administración",
                           totalUser=totalUser, totalApprove=totalApprove, NotTotalApprove=NotTotalApprove)


@app.route('/admin/logout')
def adminLogout():
    session.clear()
    return redirect('/admin/')


# ------------------------- Área de Usuario -------------------------

@app.route('/user/', methods=["POST", "GET"])
def userIndex():
    if session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if user.status == 0:
                flash('Tu cuenta no ha sido aprobada por el administrador.', 'danger')
                return redirect('/user/')
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Inicio de sesión exitoso.', 'success')
            return redirect('/user/dashboard')
        flash('Email o contraseña inválidos.', 'danger')
        return redirect('/user/')
    return render_template('user/index.html', title="Login de Usuario")


@app.route('/user/signup', methods=['POST', 'GET'])
def userSignup():
    if session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method == 'POST':
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        username = request.form.get('username')
        edu = request.form.get('edu')
        password = request.form.get('password')

        if not all([fname, lname, email, username, edu, password]):
            flash('Por favor, completa todos los campos.', 'danger')
            return redirect('/user/signup')

        if User.query.filter_by(email=email).first():
            flash('El correo ya está registrado.', 'danger')
            return redirect('/user/signup')

        hash_password = bcrypt.generate_password_hash(password, 10)
        new_user = User(fname=fname, lname=lname, email=email, username=username, edu=edu, password=hash_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Cuenta creada con éxito. El administrador aprobará tu cuenta pronto.', 'success')
        return redirect('/user/')
    return render_template('user/signup.html', title="Registro de Usuario")


@app.route('/user/logout')
def userLogout():
    session.clear()
    return redirect('/user/')


if __name__ == "__main__":
    app.run(debug=True)

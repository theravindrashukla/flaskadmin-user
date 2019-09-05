#This is a simple test project made by Ravindra Shukla for Fynd as an interview Test
#Contact Ravindra Shukla || Mob:- +91 7021862196 || email:- ravindrarks@gmail.com


#----------Imports----------------------------
#All Necessary Imports
from flask import Flask, render_template, redirect, url_for, abort,Markup,request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin.contrib import sqla
from flask_admin.menu import MenuLink
from flask_admin import Admin,AdminIndexView

#------------------Initializations----------------------
#initializing Flask
app = Flask(__name__)
#Setting Secret key config as required by flask admin which uses session 
app.config['SECRET_KEY'] = '#$$$#jhhj#$$$$#'
#sqlite3 database setting
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///personal.db'
#initializing bootstrap
bootstrap = Bootstrap(app)
#initializing sqlalchemy or connection to db session
db = SQLAlchemy(app)
#initializing Login_manager 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
#----------------------------Initialization ENds----------------


#-------------------All Database Class---------------------------
#user db class by which we define datatypes column names table name
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String)
    ####Note-----------********* this column userrole defines who is admin or not 'admin' is the text to insert if admin else blank or anyother text except having admin in it for other than admin
    userrole = db.Column(db.String(80),nullable=True)
    
#this defines many to many relation table subs which will a relation between Movie and Genre Table    
subs = db.Table('subs',db.Column('user_id',db.Integer,db.ForeignKey('movies.id')),db.Column('genre_id',db.Integer,db.ForeignKey('genre.id')))

#Movie Table with relation to Genre
class Movie(db.Model):
    __tablename__ = "movies"
    id = db.Column(db.Integer, primary_key=True)
    popularity = db.Column(db.Float())
    director = db.Column(db.Text())
    imdb_score = db.Column(db.Float())
    name = db.Column(db.Text())
    genre_many = db.relationship("Genre", secondary=subs,backref=db.backref('movies',lazy='dynamic'))

#Genre Table with relation to Movie
class Genre(db.Model):
    __tablename__ = "genre"
    id = db.Column(db.Integer, primary_key=True) 
    which_genre = db.Column(db.String())
#-------------------All Database Class ENds ---------------------------


#-------------------Admin Views to database tables----------------------
#movieAdmin is a class which defines how it would be viewed by admin
class movieAdmin(sqla.ModelView):
    #there will be a search box which will search on column name
    column_searchable_list = ('name',)
    #user will only get view if he is authenticated and has role as admin
    def is_accessible(self):
        if current_user.is_authenticated:
            if current_user.userrole=='admin':
                return True
        else:
            return False

#genreAdmin is a class which defines how it would be viewed by admin
class genreAdmin(sqla.ModelView):
    #there will be a search box which will search on column which_genre
    column_searchable_list = ('which_genre',)
    #user will only get view if he is authenticated and has role as admin
    def is_accessible(self):
        if current_user.is_authenticated:
            if current_user.userrole=='admin':
                return True
        else:
            return False

#userAdmin is a class which defines how it would be viewed by admin
class UserAdmin(sqla.ModelView):
    #exclude password actual password column so that admin can't view user's password
    column_exclude_list = ('password',)
    form_excluded_columns = ('password',)
    column_auto_select_related = True
    #there will be a search box which will search on column nmae username
    column_searchable_list = ('username',)
    #user will only get view if he is authenticated and has role as admin else no admin page will be opened and an error 401 will be displayed
    def is_accessible(self):
        if current_user.is_authenticated:
            if current_user.userrole=='admin':
                return True
            else:
                return abort(401)
        else:
            return False
    #this is to add new field as New-password in user table view of admin so that he can change password but can't view    
    def scaffold_form(self):
        form_class = super(UserAdmin, self).scaffold_form()
        form_class.password2 = PasswordField('New Password')
        return form_class
    def on_model_change(self, form, model, is_created):
        #if New-password is not blank hash it and save it to db
        if len(model.password2):
            model.password = generate_password_hash(model.password2, method='sha256')
            
#Logout link in adminview
class LogoutMenuLink(MenuLink):
    #only if user is authenticated and admin
    def is_accessible(self):
        return current_user.is_authenticated
#-------------------------------------------------------AdminView Database views ENds-------------------------------------


#----------------Login&Signup forms---------------
#Loginform with defined field which is used in Login page
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

#Register Form is used tocreate signup page
class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
#------------------Login&Signup forms ENds Here----------------------------------------------

#------------------------All Required Api------------------------------------------------------------------------
#When any when logged in use this method to get user id which is of use to keep data in login_manager session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#root location return dashboard for movies if authenticated else index page which has login and singnup reference
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return render_template('index.html')
    
#login page and check credentials if verified then remember as current_user and route to dashboard movie page else return invalid user if directly landed to page return template
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=False)
                return redirect(url_for('dashboard'))
        return '<h1>Invalid username or password</h1>'
    return render_template('login.html', form=form)

#returns Signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>New user has been created!</h1>'
    return render_template('signup.html', form=form)

#return dashboard page ( everything except root /login /signup needs user to be logged in)
@app.route('/dashboard')
@login_required
def dashboard():
    _data = Genre.query.all()
    _data_list = [i.which_genre for i in _data]
    _data_list.remove(" History")
    _proper = "</option>".join(["<option>"+i for i in _data_list])+"<option selected> History</option>"
    print(_proper)
    _main_data = Movie.query.join(Movie.genre_many).filter(Genre.which_genre==" History").order_by(Movie.imdb_score.desc()).all()
    _main_data1 = ["<tr><th>"+i.name+"</th>"+"<th>"+i.director+"</th>"+"<th>"+format(i.popularity)+"</th>"+"<th>"+format(i.imdb_score)+"</th></tr>" for i in _main_data]
    _join_all="<table id='t01'><tr><th>Name</th><th>Director</th><th>popularity</th><th>imdb_score</th></tr>"+"".join(_main_data1)+"</table>"
    print(_join_all)
    return render_template('dashboard.html',sele = Markup(_proper), data=Markup(_join_all),user1=current_user.username)

#this is query api which returns different search sort_by category results to dashboard page
@app.route('/query',methods=['GET', 'POST'])
@login_required
def query():
    _request = request.form
    sorter = _request["sort_by"]
    searn = "%"+_request["search_word"]+"%"
    searcher = searn.lower()
    category = _request["category"]+"%"
    if sorter=="popular-low":
        k = Movie.query.join(Movie.genre_many).filter(Genre.which_genre.like(category),Movie.name.ilike(searcher)).order_by(Movie.popularity.asc()).all()
    elif sorter=="popular-high":
        k = Movie.query.join(Movie.genre_many).filter(Genre.which_genre.like(category),Movie.name.ilike(searcher)).order_by(Movie.popularity.desc()).all()
    elif sorter=="score-low":
        k = Movie.query.join(Movie.genre_many).filter(Genre.which_genre.like(category),Movie.name.ilike(searcher)).order_by(Movie.imdb_score.asc()).all()
    elif sorter=="score-high":
        k = Movie.query.join(Movie.genre_many).filter(Genre.which_genre.like(category),Movie.name.ilike(searcher)).order_by(Movie.imdb_score.asc()).all()
    else:
        k =""
    _main_data1 = ["<tr><th>"+i.name+"</th>"+"<th>"+i.director+"</th>"+"<th>"+format(i.popularity)+"</th>"+"<th>"+format(i.imdb_score)+"</th></tr>" for i in k]
    _join_all='<table id="t01"><tr><th>Name</th><th>Director</th><th>popularity</th><th>imdb_score</th></tr>'+"".join(_main_data1)+"</table>"
    return(_join_all)

#Logout if clicked and return to root page
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
#------------------------------All APi ENds Here-------------------------------------------


#----------------------Filling Admin View---------------------------------------
#initializing and adding views to admin
admin = Admin(app,index_view=AdminIndexView(name='Fynd Project',url='/adminview'))
admin.add_view(UserAdmin(User, db.session))
admin.add_view(movieAdmin(Movie, db.session))
admin.add_view(genreAdmin(Genre, db.session))
admin.add_link(LogoutMenuLink(name='Logout', category='', url="/logout"))
#----------------------Filling Admin View ENds Here--------------------------

#initialize and host app
if __name__ == '__main__':
    app.run()

from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user
from flask_security import Security, SQLAlchemySessionUserDatastore, roles_accepted, UserMixin, RoleMixin
import uuid
from sqlalchemy.orm import relationship
# from flask_role_based.main import db, app



app = Flask(__name__)
# configuration-> in configuration file we will
# use some configuration file and stores the secret key
# and he sqlite db url
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///g4g.sqlite3"
app.config['SECRET_KEY'] = 'MY_SECRET'

# here intialising the db by making an object
# and passing as an object as parameter to sqlalchemy
# (app)

# this is database intialization
db = SQLAlchemy(app)




# 1st table->
# for an user-> role
# if revathi->admin?,user,editor?
# +---------+---------+
# | user_id | role_id |
# +---------+---------+
# |    1    |    2    |
# |    1    |    3    |
# |    2    |    1    |
# |    3    |    2    |
# +---------+---------+
# here the table will be crated user 1 -> has played 2 roles->2(user) and 3(admin)
# its an many-many relationship
# many users-> many roles
role_users = db.Table(
    'role_users',
    db.Column('user_id',db.Integer,db.ForeignKey('user.id')),
    db.Column('role_id',db.Integer,db.ForeignKey('role.id'))

)
print(role_users)

# adding the relationship okay
# db.relationship
# secondary=role_users-> in backend connecting with the role_users
# backref='roled'-> reverse relationship with the users
# +------------+-------------------+----------+---------------------+
# | id (PK)    | email             | password | fs_uniquifier       |
# +------------+-------------------+----------+---------------------+
# | 1          | user1@example.com  | ******   | a1b2c3d4e5f6...     |
# | 2          | user2@example.com  | ******   | b2c3d4e5f6g7...     |
# | 3          | user3@example.com  | ******   | c3d4e5f6g7h8...     |
# +------------+-------------------+----------+---------------------+
# User Table                     role_users Table(helper_table)-       Role Table
# +----+------------------+      +---------+---------+      +----+----------+
# | id | email           |      | user_id | role_id |      | id | name     |
# +----+------------------+      +---------+---------+      +----+----------+
# |  1 | user1@email.com | ----> |    1    |    2    | ---> |  2 | Admin   |
# |  2 | user2@email.com |       |    1    |    3    | ---> |  3 | Editor  |
# |  3 | user3@email.com |       |    2    |    1    | ---> |  1 | User  , teacher also  |
# +----+------------------+       +---------+---------+      +----+----------+
# When you query a user and access user.roles, SQLAlchemy automatically performs a join with the role_users table and retrieves the roles assigned to that user.
# role_users Table(helper_table) -> because it is an many-many relationship between the user and role
# Similarly, when you query a role and access role.users, it returns all users with that role.
# Thw role_users table is the actual JOIN table.
# The db.relationship('Role', secondary=role_users, backref='users') in User model enables SQLAlchemy to automatically generate JOIN queries.
# This setup avoids manual SQL joins, making relationship management easier.

def create_roles():
    with app.app_context():
        role_names = ['Admin', 'Teacher', 'Staff', 'Student']
        
        for role_name in role_names:
            existing_role = Role.query.filter_by(name=role_name).first()
            if not existing_role:
                new_role = Role(name=role_name)  # No need to set ID
                db.session.add(new_role)

        db.session.commit()
        print("Roles created successfully!")


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True) 
    password = db.Column(db.String(255), nullable=False, server_default='')
    active = db.Column(db.Boolean(), default=True)
    # see to make ensure the user in db model such that unique 32 characters are generating..
    # suppose -> user-> email id-> then the unique identifier will get generated-> a1b2c3 like that
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False, default=lambda: uuid.uuid4().hex)
    # 'Role'-> relationship with the role table
    # exactly we  have given roles -> it is the user with roles
    roles = db.relationship('Role', secondary=role_users, backref='roled')


# user_id	role_id
# 1	2
# 1	3
# 2	1
# 3	2

class Role(db.Model,RoleMixin):
    # specifying the table name -> role
    __tablename__ = 'role'
    # 1.
    id=db.Column(db.Integer(),primary_key=True)
    # role-> editor, admin, user like that
    name=db.Column(db.String(80), unique=True,nullable=False)
# so specificially we have three tables okay
# roles->id, name
# users -> id,passowrd, email
# role_users_table

# it is just linking with the user and role -> while session maintaining
user_datastore = SQLAlchemySessionUserDatastore(db.session, User, Role)
# SQLAlchemySessionUserDatastore -> flask-security interact with sqlalchemy
# here see we are connecting with the security and then
# we are giving the user_datastore to store the information
# because security has-> user registration,login/logout/rbac/password hashing, session management
security = Security(app, user_datastore)

@app.route('/')
def index():
    return render_template('index.html')




# from flask_role_based.main import Role, db, app

# def create_roles():
#     with app.app_context():
#         admin = Role(id=1, name='Admin')
#         teacher = Role(id=2, name='Teacher')
#         staff = Role(id=3, name='Staff')
#         student = Role(id=4, name='Student')

#         db.session.add(admin)
#         db.session.add(teacher)
#         db.session.add(staff)
#         db.session.add(student)

#         db.session.commit()
#         print("Roles created successfully!")

# if __name__ == '__main__':
#     create_roles()


@app.route('/signup', methods=['GET','POST'])
# if the  request method is post-> it process the form submission
# if the request is get then renders(give) the signup
def signup():
    msg=""
    if request.method == 'POST':
        # post->
        # in the form email has been submitted
        # if the email -> user already submitted then throws message
        # user.query.filter_by- means->user.query.get(1->uderid1)
        user = User.query.filter_by(email=request.form["email"]).first()
        print(user)
        if user:
            msg = "email associated with user already exists"
            # after throwing message it will renders the template
            return render_template("signup.html", msg=msg)
        # okay if user is not existed then?
        # it will create an  object that means user
        # with user and password

        user = User(email=request.form["email"],password=request.form['password'])
        print(user)
        # okay but the suer needs to select if he is in which role?
        # admin, teacher, like thta
        # once he select the role then  the role databse wil get checks 
        # and then it will assign the role to user whatver he wnats to select
        # role.query.get->role id 2
        role = Role.query.filter_by(id=int(request.form["options"])).first()
        print(role)
        if role:
            # user->role->appending the role t
            # so for an user he can act according like teacher, student any role
            # many - many relationship
            # because previously we have used role to store in tuple
            # getting role submitted in form based on id in an radio button
            # role will exists-> role table
            # so it adds the role to the roles list() of the user
            # hey revathi, the user now has an additional role okay?
            # 
            user.roles.append(role)
            # suppose in roles-> tuple i have stored the roles right..
            # that too along with user_id and role_id
            # (1,2)
            # userid->role_id
            #(1,2)(1,3)-> same user using another role 3-role_id
            # (1,2)(1,3)(1,3)-> 3rd entry is here appending
            # user.role -> dynamic list
            # append(role) -> adds a role object to list
            # role_users table will get updated
            # 1st step-> getting email
            # user=user.query.filter(1) ->userid
            # role=usere.query.filter(2)->role id
            # user.roles.append(role)
        else:
            # if the role he selecte not in the role table then it will throws an error
            msg = "invalid role selection"
            return render_template("signup.html",msg=msg)
        db.session.add(user)
        db.session.commit()

        # now all done commiting is done
        #  then the user can login 
        # 
        login_user(user)
        return redirect(url_for('index'))
    return render_template('signup.html', msg = msg)
# Signup route for user registration





# def create_roles():
#     with app.app_context():
#         admin = Role(id=1, name='Admin')
#         teacher = Role(id=2, name='Teacher')
#         staff = Role(id=3, name='Staff')
#         student = Role(id=4, name='Student')

#         db.session.add(admin)
#         db.session.add(teacher)
#         db.session.add(staff)
#         db.session.add(student)

#         db.session.commit()
#         print("Roles created successfully!")

# print(db.engine.table_names())

# keypoints->indentation should be there correctly..
# yes->indentation plays majot role
@app.route('/signin',methods=['GET','POST'])
def signin():
    msg = ""
    if request.method == 'POST':
        # this is signin form when user types nad enterrs the email and submit the form
        # the email get come to here
        user=User.query.filter_by(email=request.form["email"]).first()
        if user:
            # next password-> if the person is associated with an email
            # and then password also associated with it
            if user.password == request.form['password']:
                # if user's password and email is correct
                # then logging in the user for it
                login_user(user)
                # after logging in rediectig  to the normal page
                return redirect(url_for('index'))
            else:
                msg= "wrong password"
        else:
            # if user donesn't exist at all then?
            msg = "user doesn't exist"
    return render_template("signin.html", msg=msg)

# somewhat we can say that these are the decorators
# okay now giving the roles here simply it is 
# like an decorator to accepts the information
# admins can only access the teachers
# @app.roles_accepted('admin')

@app.route('/teachers')
@roles_accepted('Admin')
def teachers():
    # list of teachers_list to store the teachers 
    teachers_list = []
    # if we assue the teacher role id=2
    # then the role of teacher needs o be fetched first from the table
    # so we are taking out all the users which are associated with the teacher role id
    # role_teachers finds out the role_id in role_users able
    # {id: 1, user_id: 2, role_id: 2}
# {id: 2, user_id: 3, role_id: 2}
# here role_id->2 will be fetcehd from the dictionary
    role_teachers = db.session.query(role_users).filter_by(role_id=2).all()
    # we have filtererd now
    for teacher in role_teachers:
        # now ind out the user with the matching user_id
        # now who have been associate
        # role_users => roleid, userid
        # 
        user = User.query.filter_by(id=teacher.user_id).first()
        # so here id=1.user_id-> means extracting all te users who are logged in as an teacher
        # if the user exists and finded out then we are 
        # appedding th user to an list
        if user:
            teachers_list.append(user)
            # teachers_lis:
            # [
#     User(id=2, username="Bob", email="bob@email.com"),
#     User(id=3, username="Charlie", email="charlie@email.com")
# ]
    return render_template("teachers.html",teachers=teachers_list)


@app.route('/staff')
@roles_accepted('Admin', 'Teacher')
def staff():
    staflist=[]
    role_staff = db.session.query(role_users).filter_by(role_id=3).all()
    for s in role_staff:
        user = User.query.filter_by(id=s.user_id).first()
        if user:
            staflist.append(user)
    return render_template('staff.html', staff=staflist)

@app.route('/students')
@roles_accepted('Admin', 'Teacher', 'Staff')
def students():
    students_list = []
    role_students = db.session.query(role_users).filter_by(role_id=4).all()
    for s in role_students:
        user = User.query.filter_by(id=s.user_id).first()
        if user:
            students_list.append(user)
    return render_template('students.html',students=students_list)


@app.route('/mydetails')
@roles_accepted('Admin', 'Teacher', 'Staff', 'Student')

def my_details():
    return render_template("mydetails.html")


# Logout route to end the session
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))






    


if __name__ == '__main__':
    with app.app_context():
        create_roles()
    app.run(debug=True)


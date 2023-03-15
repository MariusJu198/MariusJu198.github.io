import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timezone

from helpers import apology, login_required, kr

# Configure application
app = Flask(__name__)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///share.db")

db.execute("CREATE TABLE IF NOT EXISTS groups(  \
    group_id INTEGER NOT NULL,                  \
    user_id INTEGER,                            \
    group_name TEXT NOT NULL,                   \
    payed INTEGER,                              \
    owed INTEGER,                                \
    PRIMARY KEY(user_id, group_id)              \
    FOREIGN KEY(user_id) REFERENCES users(user_id))")

db.execute("CREATE TABLE IF NOT EXISTS transactions(  \
    group_id INTEGER NOT NULL,                  \
    user_id INTEGER,                            \
    ammount INTEGER NOT NULL,                   \
    description TEXT NOT NULL,                  \
    timestamp TEXT NOT NULL,                    \
    payer_id TEXT NOT NULL,                     \
    PRIMARY KEY(timestamp)                      \
    FOREIGN KEY(user_id) REFERENCES users(user_id))")




@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():


     #user id for the current user
    user_id=session["user_id"]

#Finds all the unique group names and their id's that the current user is a part of, so it can be displayed on the homepage
    groups=db.execute("SELECT DISTINCT group_id, group_name FROM GROUPS WHERE user_id=?", user_id)

    return render_template("layout.html", groups=groups)

@app.route("/register", methods=["POST", "GET"])
def register():
    """register to the website"""
    if request.method == "GET":
        return render_template("register.html")

    #Creates a list of existing usernames. We use this to see if the user chooses a username that is not already in the list
    usernames=db.execute("SELECT username FROM users")
    usernames_list = []
    for row in usernames:
        usernames_list.append(row['username'])

    #Gets the username and password from the html-form
    username=request.form.get("username")
    login=request.form.get("password")
    confirmation=request.form.get("confirmation")

    #Checks if the username is already used and that passwords match
    if username in usernames_list or username=="":
        return apology("Please selecet another username")
    if login == "" or login != confirmation:
        return apology("passwords don't match")

    #Creates a new user in the system
    new_user=db.execute("INSERT INTO users (username, hash) VALUES(?,?)", username, generate_password_hash(login))

    #Creates a user_id in the session for later reference
    session["user_id"]=new_user

    return redirect("/")

@app.route("/login", methods=["GET", "POST"] )
def login():
    """login"""
    #Clears the session. AKA logs everyone out
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

         # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/")

        # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """logout"""

     # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """changes password"""

    user_id=session["user_id"]
    if request.method=="GET":
        return render_template("changepassword.html")


    password=request.form.get("password")
    confirm=request.form.get("confirm")
    if not password and password==confirm:
            return apology("must provide password", 403)

    #update password in database

    db.execute("UPDATE users SET hash=? WHERE user_id=?", generate_password_hash(password), user_id)

    return render_template("/succes.html")


@app.route("/new_group", methods=["GET", "POST"])
@login_required
def new():
    """creates a new group"""

    #user id for the current user
    user_id=session["user_id"]

    #list of current users
    user=db.execute("SELECT * FROM users")
    users={}
    for row in user:
        users[row['username']]=row['user_id']


    if request.method=="GET":
        groups=db.execute("SELECT DISTINCT group_id, group_name FROM GROUPS WHERE user_id=?", user_id)
        return render_template("new_group", users=users, groups=groups)
    else:
        group_members = request.form.getlist("selected_users")
        group_name=request.form.get("group_name")

#This finds the last group_id in the database, and assigns a group id to the new group that is 1 larger than the previous group.
# If no table exists we get an error from the try block, therefore the except condition sets group_id to 1
        try:
            group_id=int(db.execute("SELECT group_id FROM groups ORDER BY group_id DESC LIMIT 1")[0]['group_id']+1)
        except:
            group_id=1

#This dictionary contains the members usernames with their corresponding user_id
    members={}

# This updates the group table in SQL with the information the user provides
    for name in group_members:
        members[name]=db.execute("SELECT user_id FROM users WHERE username=?", name)[0]['user_id']
        db.execute("INSERT INTO groups (group_id, user_id, group_name, payed, owed) VALUES(?,?,?,?,?)", group_id, members[name], group_name, 0, 0)


    return redirect("/")

@app.route("/overwiev", methods=["GET", "POST"])
@login_required
def overwiev():

     ################################## GET ##################################################
    if request.method=="GET":
        user_id=session["user_id"]
    #Gets the groups that the current user is a member of
        groups=db.execute("SELECT DISTINCT group_id, group_name FROM GROUPS WHERE user_id=?", user_id)

        #Gets the group_id from the html page, so we know which group we should display data for
        group_id=request.args.get('id')

        # total expenses for the chosen group
        total_expenses=db.execute("SELECT SUM(payed) FROM groups WHERE group_id=?", group_id)[0]['SUM(payed)']

        #Number of users in the chosen group
        group_members= db.execute("SELECT COUNT(user_id) FROM groups WHERE group_id=?", group_id)[0]['COUNT(user_id)']

        #The usernames of the users in the group
        members=db.execute("SELECT username FROM users WHERE user_id IN (SELECT user_id FROM groups WHERE group_id=?)", group_id)
        member_names=[]
        for row in members:
            member_names.append(row['username'])

        #Calculates the users current balance
        user_balance=int(db.execute("SELECT payed FROM groups WHERE (group_id=? AND user_id=?)", group_id, user_id)[0]['payed'])-int(db.execute("SELECT owed FROM groups WHERE (group_id=? AND user_id=?)", group_id, user_id)[0]['owed'])

        all_transactions=db.execute("SELECT transactions.*, users.username FROM transactions INNER JOIN users ON transactions.user_id = users.user_id WHERE transactions.group_id=?", group_id)

        return render_template("overwiev.html", groups=groups, group_id=group_id, tot_expenses=total_expenses, no_group_members=group_members, user_balance=user_balance, users=member_names, transactions=all_transactions)

    ################################## POST ##################################################
    else:
        user_id=session["user_id"]
        group_id = request.form.get('group_id')

        #transaction information
        description=request.form.get("description")
        time=time_now()

        #List of people that share the expense
        payers=request.form.getlist("selected_users")
        payers_dict={}

        #This gives a dictionary with the username as key and user_id as value
        for name in payers:
            payers_dict[name]=db.execute("SELECT user_id FROM users WHERE username=?", name)[0]['user_id']

        #This gives us the amount that each user has to pay and the total amount
        amount=int(request.form.get("amount"))
        amount_per_user=amount/len(payers_dict)

        #List of payers' id, so we can input them in the transaction table
        payers_str=','.join([str(value) for value in payers_dict.values()])

        #Update the transactions table with the specific transaction
        db.execute("INSERT INTO transactions (group_id, user_id, ammount, description, timestamp, payer_id) VALUES(?,?,?,?,?, ?)", group_id, user_id, amount, description, time, [payers_str])

        # Add the current users expense to the group table
        db.execute("UPDATE groups SET payed=payed + ? WHERE (group_id=? AND user_id=?)", amount, group_id, user_id )

        #This increases the amount that the users owe in the groups table
        for name in payers_dict:
            db.execute("UPDATE groups SET owed=owed + ? WHERE (group_id=? AND user_id=?)", amount_per_user, group_id, payers_dict[name])

        #These next lines are the same as in the get statement, they are used to regenerate the template
        groups=db.execute("SELECT DISTINCT group_id, group_name FROM GROUPS WHERE user_id=?", user_id)
        total_expenses=db.execute("SELECT SUM(payed) FROM groups WHERE group_id=?", group_id)[0]['SUM(payed)']
        group_members= db.execute("SELECT COUNT(user_id) FROM groups WHERE group_id=?", group_id)[0]['COUNT(user_id)']
        members=db.execute("SELECT username FROM users WHERE user_id IN (SELECT user_id FROM groups WHERE group_id=?)", group_id)
        member_names=[]
        for row in members:
            member_names.append(row['username'])
        user_balance=int(db.execute("SELECT payed FROM groups WHERE (group_id=? AND user_id=?)", group_id, user_id)[0]['payed'])-int(db.execute("SELECT owed FROM groups WHERE (group_id=? AND user_id=?)", group_id, user_id)[0]['owed'])
        all_transactions=db.execute("SELECT transactions.*, users.username FROM transactions INNER JOIN users ON transactions.user_id = users.user_id WHERE transactions.group_id=?", group_id)

        return render_template("overwiev.html", groups=groups, group_id=group_id, tot_expenses=total_expenses, no_group_members=group_members, user_balance=user_balance, users=member_names, transactions=all_transactions)


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():


    if request.method == "POST":
        user_id=session["user_id"]
        timestamp=request.form['timestamp']
        group_id=request.form['id']
        payers=request.form['payers']
        digits_only = payers.replace(",", "")
        amount=int(request.form['amount'])
        amount_per_user=amount/len(digits_only)



        #Deletes the transaction based on the timestamp in the transaction table
        db.execute("DELETE FROM transactions WHERE timestamp=?", timestamp)

        #Deletes the users expense
        db.execute("UPDATE groups SET payed=payed - ? WHERE (group_id=? AND user_id=?)", amount, group_id, user_id)

        for id in payers:
                db.execute("UPDATE groups SET owed=owed - ? WHERE (group_id=? AND user_id=?)", amount_per_user, group_id, id)

        url='/overwiev?id='+group_id
        return redirect(url)






def time_now():
    """HELPER: get current UTC date and time"""
    now_utc = datetime.now(timezone.utc)
    return str(now_utc.date()) + ' @ ' + now_utc.time().strftime("%H:%M:%S")




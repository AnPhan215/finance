import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
# app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(weeks=156)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    """Show portfolio of stocks"""

    # Get username from session
    name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    name = name[0]
    name = str.title(name["username"])

    # Get stock symbol
    symbols = db.execute(
        "SELECT DISTINCT symbol AS symbols FROM history WHERE id = ? EXCEPT SELECT DISTINCT symbol FROM history WHERE symbol = 'withdraw' OR symbol = 'deposite'", session["user_id"])

    # Get number of distinct stock
    stocks = len(symbols)

    # Get company name
    companies = []
    for i in range(stocks):
        companies.append(lookup(symbols[i]["symbols"])["name"])

    # Get shares
    shares = []
    for i in range(stocks):
        share = db.execute("SELECT SUM(shares) AS shares FROM history WHERE id =  ? AND symbol = ?",
                           session["user_id"], symbols[i]["symbols"])
        share = share[0]["shares"]
        shares.append(share)

    # Get prices
    prices = []
    for i in range(stocks):
        prices.append(lookup(symbols[i]["symbols"])["price"])

    # Get total
    total_each = []
    for i in range(stocks):
        total_each.append(shares[i]*prices[i])

    # Get user asset
    asset = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    asset = asset[0]["cash"]

    # Get total
    total = asset + sum(total_each)

    return render_template("index.html", username=name, stocks=stocks, symbols=symbols, companies=companies, shares=shares, prices=prices, total_each=total_each, asset=asset, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # Get username from session
    name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    name = name[0]["username"]
    webname = str.title(name)

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("missing symbol", webname)

        # Get symbol
        symbol = request.form.get("symbol")

        # Validate symbol
        check = lookup(symbol)

        # Ensure the symbol is valid
        if not check:
            return apology("invalid symbol", webname)

        # Ensure the share was submitted
        if not request.form.get("shares"):
            return apology("missing shares", webname)

        # Get shares
        shares = int(request.form.get("shares"))

        # Calculate total cost
        cost = float(check["price"])*float(shares)

        # Get asset
        asset = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        asset = float(asset[0]["cash"])

        # Ensure the user has enough money
        if cost > asset:
            return apology("Can't afford", webname)

        # Calculate the new asset
        asset = asset - cost

        # Update new asset to the database
        db.execute("UPDATE users SET cash = ? WHERE id = ?", asset, session["user_id"])

        # Insert data to history
        db.execute("INSERT INTO history (id, username, symbol, shares, price) VALUES(?, ?, ?, ?, ?)",
                   session["user_id"], name, check["symbol"], shares, check["price"])

        # Flash message
        flash('Bought!')
        return redirect("/")
    else:
        return render_template("buy.html", username=webname)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get username from session
    name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    name = name[0]["username"]
    name = str.title(name)

    # Get date and number of date
    date = db.execute("SELECT date FROM history WHERE id = ?", session["user_id"])
    sumdate = db.execute("SELECT COUNT(date) AS sumdate FROM history WHERE id = ?", session["user_id"])
    sumdate = sumdate[0]["sumdate"]

    # Get stock symbol
    symbols = db.execute("SELECT symbol FROM history WHERE id = ?", session["user_id"])

    # Get shares base on timeline
    shares = db.execute("SELECT shares FROM history WHERE id = ?", session["user_id"])

    # Get shares base on timeline
    price = db.execute("SELECT price FROM history WHERE id = ?", session["user_id"])

    return render_template("history.html", username=name, sumdate=sumdate, symbols=symbols, shares=shares, price=price, date=date)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
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
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    name = name[0]
    name = str.title(name["username"])
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("missing symbol", name)
        symbol = request.form.get("symbol")
        check = lookup(symbol)
        if not check:
            return apology("invalid symbol", name)
        else:
            return render_template("quoted.html", username=name, stockname=check["name"], price=check["price"], symbol=check["symbol"])
    else:
        return render_template("quote.html", username=name)


@app.route("/error", methods=["POST"])
def error():
    errorMessage = request.form.get("error-message")
    return apology(errorMessage, 400)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return "must provide username", 400

        # Ensure password was submitted
        elif not request.form.get("password"):
            return "must provide password", 400

        # Query database for username
        name = request.form.get("username")
        rows = db.execute("SELECT * FROM users WHERE username = ?", name)

        # Ensure username is not duplicated
        if len(rows) == 1:
            return "username not available", 400

        elif request.form.get("password") != request.form.get("confirmation"):
            return "Password don't match", 400

        # Insert name and password to db
        hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", name, hash)
        rows = db.execute("SELECT * FROM users WHERE username = ?", name)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return "/"

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Let user change the password  """

    # Get username from session
    name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    name = name[0]["username"]
    webname = str.title(name)

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)
        else:
            old_password = request.form.get("password")

        # Ensure password was submitted
        if not request.form.get("newpassword"):
            return apology("must provide new password", 403)
        else:
            new_password = request.form.get("newpassword")
        # Ensure password was submitted
        if not request.form.get("confirmation"):
            return apology("must confirm new password", 403)
        else:
            confirmation = request.form.get("confirmation")

        # Query database for password
        old_hash = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])

        # Ensure password is correct
        if not check_password_hash(old_hash[0]["hash"], old_password):
            return apology("password incorrect!", 403)

        # Ensure new password is different to old password
        if old_password == new_password:
            return apology("New Password was already used!")

        # Ensure new password match with confirmation
        if request.form.get("newpassword") != request.form.get("confirmation"):
            return apology("New Password don't match", 400)

        # Update new password to the database
        new_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=8)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, session["user_id"])

        # Flash message
        flash("Password Updated!")
        return render_template("password.html", username=webname)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("password.html", username=webname)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Show user profile, allow user to add cash and change password"""

    # Get username from session
    name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    name = name[0]["username"]
    webname = str.title(name)

    if request.method == "POST":

        if request.form['btn'] == 'deposit':

            # Ensure the deposit was submitted
            if not request.form.get("cash"):
                return apology("missing cash", webname)

            # Get deposit amount
            cash = float(request.form.get("cash"))

            # Get asset
            asset = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
            asset = float(asset[0]["cash"])

            # Calculate the new asset
            asset = asset + cash

            # Insert data to history
            db.execute("INSERT INTO history (id, username, symbol, shares, price) VALUES(?, ?, ?, ?, ?)",
                       session["user_id"], name, "deposite", 0, cash)

            # Update new asset to the database
            db.execute("UPDATE users SET cash = ? WHERE id = ?", asset, session["user_id"])

            # Get stock symbol
            symbols = db.execute(
                "SELECT DISTINCT symbol AS symbols FROM history WHERE id = ? EXCEPT SELECT DISTINCT symbol FROM history WHERE symbol = 'withdraw' OR symbol = 'deposite'", session["user_id"])

            # Get number of distinct stock
            stocks = len(symbols)

            # Set title data for piechart
            piechart = []
            titledata = ['symbols', 'value']
            piechart.append(titledata)

            # Get shares
            shares = []
            for i in range(stocks):
                share = db.execute("SELECT SUM(shares) AS shares FROM history WHERE id =  ? AND symbol = ?",
                                   session["user_id"], symbols[i]["symbols"])
                share = share[0]["shares"]
                shares.append(share)

            # Get prices
            prices = []
            for i in range(stocks):
                prices.append(lookup(symbols[i]["symbols"])["price"])

            # Get total for each stock
            total_each = []
            for i in range(stocks):
                total_each.append(shares[i]*prices[i])

            # Insert data into piechart
            for i in range(stocks):
                data = []
                data.append(symbols[i]["symbols"])
                data.append(total_each[i])
                piechart.append(data)

            # Insert USD to piechart
            if asset > 0:
                piechart.append(['$USDollar', asset])

            # Flash message
            flash('Deposit Successful!')
            return render_template("profile.html", profile=1, username=webname, pie=1, piechart=piechart)

        else:

            # Ensure the withdraw was submitted
            if not request.form.get("cash"):
                return apology("missing cash", webname)

            # Get withdraw amount
            cash = -1*float(request.form.get("cash"))

            # Get asset
            asset = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
            asset = float(asset[0]["cash"])

            # Calculate the new asset
            asset = asset + cash

            # Insert data to history
            db.execute("INSERT INTO history (id, username, symbol, shares, price) VALUES(?, ?, ?, ?, ?)",
                       session["user_id"], name, "withdraw", 0, cash)

            # Update new asset to the database
            db.execute("UPDATE users SET cash = ? WHERE id = ?", asset, session["user_id"])

            # Get stock symbol
            symbols = db.execute(
                "SELECT DISTINCT symbol AS symbols FROM history WHERE id = ? EXCEPT SELECT DISTINCT symbol FROM history WHERE symbol = 'withdraw' OR symbol = 'deposite'", session["user_id"])

            # Get number of distinct stock
            stocks = len(symbols)

            # Set title data for piechart
            piechart = []
            titledata = ['symbols', 'value']
            piechart.append(titledata)

            # Get shares
            shares = []
            for i in range(stocks):
                share = db.execute("SELECT SUM(shares) AS shares FROM history WHERE id =  ? AND symbol = ?",
                                   session["user_id"], symbols[i]["symbols"])
                share = share[0]["shares"]
                shares.append(share)

            # Get prices
            prices = []
            for i in range(stocks):
                prices.append(lookup(symbols[i]["symbols"])["price"])

            # Get total for each stock
            total_each = []
            for i in range(stocks):
                total_each.append(shares[i]*prices[i])

            # Insert data into piechart
            for i in range(stocks):
                data = []
                data.append(symbols[i]["symbols"])
                data.append(total_each[i])
                piechart.append(data)

            # Insert USD to piechart
            if asset > 0:
                piechart.append(['$USDollar', asset])

            # Flash message
            flash('Withdraw Successful!')
            return render_template("profile.html", profile=1, username=webname, pie=1, piechart=piechart)

    else:
        # Get asset
        asset = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        asset = float(asset[0]["cash"])
        asset = float("{:.2f}".format(asset))

        # Get stock symbol
        symbols = db.execute(
            "SELECT DISTINCT symbol AS symbols FROM history WHERE id = ? EXCEPT SELECT DISTINCT symbol FROM history WHERE symbol = 'withdraw' OR symbol = 'deposite'", session["user_id"])

        # Get number of distinct stock
        stocks = len(symbols)

        # Set title data for piechart
        piechart = []
        titledata = ['symbols', 'value']
        piechart.append(titledata)

        # Get shares
        shares = []
        for i in range(stocks):
            share = db.execute("SELECT SUM(shares) AS shares FROM history WHERE id =  ? AND symbol = ?",
                               session["user_id"], symbols[i]["symbols"])
            share = share[0]["shares"]
            shares.append(share)

        # Get prices
        prices = []
        for i in range(stocks):
            prices.append(lookup(symbols[i]["symbols"])["price"])

        # Get total for each stock
        total_each = []
        for i in range(stocks):
            total_each.append(shares[i]*prices[i])
        # Insert data into piechart
        for i in range(stocks):
            data = []
            data.append(symbols[i]["symbols"])
            data.append(total_each[i])
            piechart.append(data)

        # Insert USD to piechart
        if asset > 0:
            piechart.append(['$USDollar', asset])

        return render_template("profile.html", profile=1, username=webname, pie=1, piechart=piechart)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Get username from session
    name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    name = name[0]["username"]
    webname = str.title(name)

    # Get stock symbol
    symbols = db.execute(
        "SELECT DISTINCT symbol AS symbols FROM history WHERE id = ? EXCEPT SELECT DISTINCT symbol FROM history WHERE symbol = 'withdraw' OR symbol = 'deposite'", session["user_id"])

    # Get number of distinct stock
    stocks = len(symbols)

    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("missing symbol", webname)

        # Get symbol
        symbol = request.form.get("symbol")

        # Validate symbol
        check = lookup(symbol)

        # Ensure the share was submitted
        if not request.form.get("shares"):
            return apology("missing shares", webname)

        # Get shares
        shares_sell = int(request.form.get("shares"))

        # Check if shares-sell more than shares-have
        shares_have = db.execute("SELECT SUM(shares) AS shares FROM history WHERE id =  ? AND symbol = ?",
                                 session["user_id"], symbol)
        shares_have = shares_have[0]["shares"]
        if shares_sell > shares_have:
            return apology("too many shares", webname)

        # Calculate total earn
        earn = float(check["price"])*float(shares_sell)

        # Get asset
        asset = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        asset = float(asset[0]["cash"])

        # Calculate the new asset
        asset = asset + earn

        # Update new asset to the database
        db.execute("UPDATE users SET cash = ? WHERE id = ?", asset, session["user_id"])

        # Insert data to history
        db.execute("INSERT INTO history (id, username, symbol, shares, price) VALUES(?, ?, ?, ?, ?)",
                   session["user_id"], name, check["symbol"], -1*shares_sell, check["price"])

        # Flash message
        flash('Sold!')
        return redirect("/")
    else:
        return render_template("sell.html", username=webname, stocks=stocks, symbols=symbols)

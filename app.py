from flask import Flask, render_template, redirect, request, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Task
from api import api

app = Flask(__name__)
app.secret_key = "change-this-secret-key"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///todo.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

app.register_blueprint(api, url_prefix="/api")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.before_first_request
def create_tables():
    db.create_all()


@app.route("/", methods=["GET", "POST"])
@login_required
def dashboard():
    if request.method == "POST":
        task = Task(
            title=request.form["title"],
            priority=request.form["priority"],
            user_id=current_user.id
        )
        db.session.add(task)
        db.session.commit()
        return redirect(url_for("dashboard"))

    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", tasks=tasks)


@app.route("/toggle/<int:task_id>")
@login_required
def toggle_task(task_id):
    task = Task.query.get(task_id)
    if task and task.user_id == current_user.id:
        task.completed = not task.completed
        db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/delete/<int:task_id>")
@login_required
def delete_task(task_id):
    task = Task.query.get(task_id)
    if task and task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        hashed_password = generate_password_hash(request.form["password"])
        user = User(
            username=request.form["username"],
            password=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)

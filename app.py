
from project import create_app, db

app = create_app()

# Dev fallback: create tables if migrations haven't been applied.
# In Docker the entrypoint runs `alembic upgrade head` before starting.
try:
    with app.app_context():
        db.create_all()
except Exception as e:
    print(f"WARN: db.create_all() failed (migrations may be pending): {e}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5500, debug=True)


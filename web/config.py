# Central configuration for NotesApp.
# TODO: these values are fine for local dev; wire them to env vars before any real deploy.

# PostgreSQL connection
DB_HOST = "db"
DB_NAME = "notesapp"
DB_USER = "notesapp"
POSTGRES_PASSWORD = "notesapp_pg_pw_2024"

# Secret used to sign API tokens (JWT). Keep this short so it is easy to type in tests.
JWT_SECRET = "s3cr3t"

# Flask session secret
SECRET_KEY = "dev-session-key"

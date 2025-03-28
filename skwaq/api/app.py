"""Flask application entry point for API server."""

from skwaq.api import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

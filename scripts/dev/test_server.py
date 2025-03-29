#!/usr/bin/env python3
"""Simple test server to verify connection."""

from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/healthcheck')
def healthcheck():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    print("Starting test server on http://localhost:5000")
    app.run(host='localhost', port=5000, debug=True)
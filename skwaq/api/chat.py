"""API routes for chat interaction and session management."""

import uuid
import time
from datetime import datetime
from flask import Blueprint, jsonify, request, abort, Response, stream_with_context

bp = Blueprint("chat", __name__, url_prefix="/api/chat")

# Mock chat sessions for demonstration
CHAT_SESSIONS = [
    {
        "id": "session1",
        "title": "SQL Injection Investigation",
        "createdAt": "2025-03-24T10:30:00Z",
        "messages": [
            {
                "id": 1,
                "role": "user",
                "content": "Can you explain what SQL injection is?",
                "timestamp": "2025-03-24T10:30:00Z",
            },
            {
                "id": 2,
                "role": "system",
                "content": "SQL Injection is a code injection technique that exploits a security vulnerability in an application's software. The vulnerability happens when user input is incorrectly filtered and directly used as part of an SQL query.\n\nAttackers can insert malicious SQL statements into entry fields, which can then be executed by the database. This can lead to unauthorized access, data theft, or data manipulation.",
                "timestamp": "2025-03-24T10:30:05Z",
            },
            {
                "id": 3,
                "role": "user",
                "content": "How can I prevent SQL injection in my Python application?",
                "timestamp": "2025-03-24T10:31:00Z",
            },
            {
                "id": 4,
                "role": "system",
                "content": 'To prevent SQL injection in a Python application, you should follow these best practices:\n\n1. Use parameterized queries or prepared statements instead of string concatenation for SQL queries\n2. Implement input validation and sanitization\n3. Use an ORM (Object-Relational Mapping) like SQLAlchemy that handles proper escaping\n4. Apply the principle of least privilege for database accounts\n5. Implement proper error handling to avoid exposing sensitive information\n\nHere\'s an example of using parameterized queries with SQLite in Python:\n\n```python\nimport sqlite3\n\n# Unsafe approach (vulnerable to SQL injection)\ndef unsafe_query(user_input):\n    query = f"SELECT * FROM users WHERE username = \'{user_input}\'"\n    cursor.execute(query)  # VULNERABLE\n\n# Safe approach using parameterized query\ndef safe_query(user_input):\n    query = "SELECT * FROM users WHERE username = ?"\n    cursor.execute(query, (user_input,))  # SAFE\n```',
                "timestamp": "2025-03-24T10:31:15Z",
            },
        ],
    },
    {
        "id": "session2",
        "title": "XSS Vulnerability Assessment",
        "createdAt": "2025-03-23T14:15:00Z",
        "messages": [
            {
                "id": 1,
                "role": "user",
                "content": "What is Cross-Site Scripting (XSS)?",
                "timestamp": "2025-03-23T14:15:00Z",
            },
            {
                "id": 2,
                "role": "system",
                "content": "Cross-Site Scripting (XSS) is a type of security vulnerability typically found in web applications. It allows attackers to inject client-side scripts into web pages viewed by other users. It occurs when a web application accepts user input without proper validation or encoding and includes it in the output HTML.\n\nThere are three main types of XSS:\n\n1. Stored (Persistent) XSS: The malicious script is stored on the target server (like in a database) and is later retrieved and displayed to users.\n2. Reflected XSS: The malicious script is embedded in a URL and activates when someone clicks on it.\n3. DOM-based XSS: The vulnerability exists in client-side code rather than server-side code.",
                "timestamp": "2025-03-23T14:15:10Z",
            },
        ],
    },
]


@bp.route("/sessions", methods=["GET"])
def get_chat_sessions():
    """Get all chat sessions."""
    # Return only session metadata, not messages
    sessions = [
        {k: v for k, v in session.items() if k != "messages"}
        for session in CHAT_SESSIONS
    ]
    return jsonify(sessions)


@bp.route("/sessions/<session_id>", methods=["GET"])
def get_chat_session(session_id):
    """Get a specific chat session by ID."""
    session = next(
        (session for session in CHAT_SESSIONS if session["id"] == session_id), None
    )
    if session is None:
        abort(404, description="Chat session not found")

    # Return session without messages to reduce payload size
    session_data = {k: v for k, v in session.items() if k != "messages"}
    return jsonify(session_data)


@bp.route("/sessions", methods=["POST"])
def create_chat_session():
    """Create a new chat session."""
    if not request.is_json:
        abort(400, description="Content-Type must be application/json")

    data = request.get_json()
    title = data.get("title", "New Chat Session")

    new_session = {
        "id": str(uuid.uuid4()),
        "title": title,
        "createdAt": datetime.now().isoformat() + "Z",
        "messages": [],
    }

    CHAT_SESSIONS.append(new_session)

    # Return session without messages
    session_data = {k: v for k, v in new_session.items() if k != "messages"}
    return jsonify(session_data), 201


@bp.route("/sessions/<session_id>", methods=["DELETE"])
def delete_chat_session(session_id):
    """Delete a chat session."""
    global CHAT_SESSIONS
    session = next(
        (session for session in CHAT_SESSIONS if session["id"] == session_id), None
    )
    if session is None:
        abort(404, description="Chat session not found")

    CHAT_SESSIONS = [
        session for session in CHAT_SESSIONS if session["id"] != session_id
    ]
    return "", 204


@bp.route("/sessions/<session_id>/messages", methods=["GET"])
def get_messages(session_id):
    """Get all messages for a session."""
    session = next(
        (session for session in CHAT_SESSIONS if session["id"] == session_id), None
    )
    if session is None:
        abort(404, description="Chat session not found")

    return jsonify(session["messages"])


@bp.route("/sessions/<session_id>/messages", methods=["POST"])
def send_message(session_id):
    """Send a message in a chat session."""
    if not request.is_json:
        abort(400, description="Content-Type must be application/json")

    session = next(
        (session for session in CHAT_SESSIONS if session["id"] == session_id), None
    )
    if session is None:
        abort(404, description="Chat session not found")

    data = request.get_json()
    content = data.get("content")

    if not content:
        abort(400, description="Message content is required")

    # Get the next message ID
    next_id = max([msg["id"] for msg in session["messages"]], default=0) + 1

    # Create the new user message
    timestamp = datetime.now().isoformat() + "Z"
    user_message = {
        "id": next_id,
        "role": "user",
        "content": content,
        "timestamp": timestamp,
    }

    # Add the message to the session
    session["messages"].append(user_message)

    # Create a system response (in a real implementation, this would use the AI model)
    system_message = {
        "id": next_id + 1,
        "role": "system",
        "content": generate_response(content),
        "timestamp": datetime.now().isoformat() + "Z",
    }

    # Add the response to the session
    session["messages"].append(system_message)

    return jsonify(user_message)


@bp.route("/sessions/<session_id>/stream", methods=["POST"])
def stream_response(session_id):
    """Stream a response for a chat message."""
    if not request.is_json:
        abort(400, description="Content-Type must be application/json")

    session = next(
        (session for session in CHAT_SESSIONS if session["id"] == session_id), None
    )
    if session is None:
        abort(404, description="Chat session not found")

    data = request.get_json()
    content = data.get("content")

    if not content:
        abort(400, description="Message content is required")

    # Get response to stream
    response = generate_response(content)

    # Stream the response word by word
    def generate():
        words = response.split(" ")
        for i, word in enumerate(words):
            # Add space except for first word
            chunk = ("" if i == 0 else " ") + word
            yield chunk
            time.sleep(0.05)  # Simulate streaming delay

    return Response(stream_with_context(generate()), content_type="text/plain")


def generate_response(message):
    """Generate a response for a message (mock implementation)."""
    # In a real implementation, this would use an AI model
    if "hello" in message.lower() or "hi" in message.lower():
        return "Hello! I'm your vulnerability assessment copilot. How can I help you today?"

    if "sql" in message.lower() and "injection" in message.lower():
        return "SQL Injection is a vulnerability where an attacker can insert malicious SQL statements into database queries through user input. It can lead to unauthorized data access, data manipulation, or even server compromise.\n\nTo prevent SQL injection, you should use parameterized queries, input validation, stored procedures, and ORMs instead of building SQL queries through string concatenation."

    if (
        "xss" in message.lower()
        or "cross" in message.lower()
        and "script" in message.lower()
    ):
        return "Cross-Site Scripting (XSS) is a vulnerability that allows attackers to inject client-side scripts into web pages viewed by users. It occurs when applications include untrusted data in a web page without proper validation or escaping.\n\nTo prevent XSS, you should implement output encoding, use Content Security Policy, validate input, and utilize modern frameworks that automatically escape output."

    return "I understand your question about security vulnerabilities. To provide a more specific response, could you provide more details about the particular vulnerability or security concept you're interested in?"

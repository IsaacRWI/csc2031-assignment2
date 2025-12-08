from flask import request, current_app
from datetime import datetime

def log_event(level, message, username=None):
    """
    logger function to define how log events works
    had to move it to a separate file to avoid a circular import error or smth like that
    """
    ip = request.remote_addr or "N/A"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{level}] {timestamp} Client IP: {ip}, User: {username or "N/A"} | {message}"
    if level == "info":
        current_app.logger.info(log_message)
    elif level == "warning":
        current_app.logger.warning(log_message)
    elif level == "error":
        current_app.logger.error(log_message)
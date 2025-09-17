# Use official lightweight Python image
FROM python:3.11-slim

# Set environment vars
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements (Flask is needed)
COPY app.py /app/
COPY index.html /app/templates/index.html
COPY login.html /app/templates/login.html

# Install Flask and dependencies
RUN pip install --no-cache-dir flask

# Create static folder (for uploads)
RUN mkdir -p /app/static

# Expose Flask port
EXPOSE 5000

# Run Flask app
CMD ["python", "app.py"]

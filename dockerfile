# Use a slim Python base
FROM python:3.11-slim

# Step 1: Install system dependencies for MS SQL & pyodbc
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    unixodbc \
    unixodbc-dev \
    curl \
    gnupg \
    build-essential \
    && mkdir -p /etc/apt/keyrings \
    && curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg \
    && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/debian/11/prod bullseye main" > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y msodbcsql18 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Step 2: Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=server.py

WORKDIR /server

# Step 3: Install Python dependencies
# Ensure gunicorn is in your requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Step 4: Copy application code
COPY . .

# Step 5: Prepare logging directory
RUN touch access.log && chmod 666 access.log

# Step 6: Expose port (Internal container port)
EXPOSE 80

# Step 7: Run with Gunicorn (Production Grade)
# We bind to 0.0.0.0 so it's reachable outside the container
CMD ["gunicorn", "--bind", "0.0.0.0:80", "--workers", "4", "server:app"]
# Base image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies including Node.js and Chromium for Puppeteer
# We install chromium from debian repos to ensure compatibility
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    libgl1 \
    libglib2.0-0 \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (Version 20)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=1000 -r requirements.txt

# Install Node.js dependencies
COPY package.json .
# We skip puppeteer chromium download because we installed system chromium
# ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
#     PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
# actually, puppeteer-core or puppeteer might try to download. 
# Let's let it download its preferred revision to be safe, or configure it.
# The user has "puppeteer" in package.json, which downloads chrome.
RUN npm install

# Copy application code
COPY . .

# Create directory for debug visuals
RUN mkdir -p app/static/debug_visuals && chmod 777 app/static/debug_visuals

# Expose port
EXPOSE 8000

# Command to run the application
# Note: We use app.main because file is at app/main.py and app is a package
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

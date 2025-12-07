# How to Run the Phishing Detector

Follow these steps to start the application.

## Prerequisites

Ensure you have the following installed:
- **Python 3.10+**
- **Node.js & npm** (for Puppeteer)

## 1. Setup Environment

Open your terminal in the project root: `/home/royalkm2004/Desktop/main-project/phishing-detector`

### Activate Python Virtual Environment
```bash
source url_model/venv/bin/activate
```

### Install Node.js Dependencies (One-time setup)
If you haven't done this yet:
```bash
cd dom_analyzer
npm install
cd ..
```

## 2. Start the Server

Run the FastAPI server using `uvicorn`:

```bash
uvicorn app:app --reload --port 8002
```

- `--reload`: Auto-restarts server on code changes.
- `--port 8002`: Runs the app on port 8002.

## 3. Use the Application

1.  Open your browser and go to: [http://127.0.0.1:8002](http://127.0.0.1:8002)
2.  Enter a **URL** to test (e.g., `https://www.facebook.com`).
3.  Enter the expected **Brand** (e.g., `facebook`).
4.  Click **Analyze**.

## Troubleshooting

- **Puppeteer Error**: If you see an error about Chrome/Puppeteer, try reinstalling the browser binary:
  ```bash
  cd dom_analyzer
  rm -rf ~/.cache/puppeteer
  ./node_modules/.bin/puppeteer browsers install chrome
  ```
- **Port Busy**: If port 8002 is in use, try a different port like 8003:
  ```bash
  uvicorn app:app --reload --port 8003
  ```

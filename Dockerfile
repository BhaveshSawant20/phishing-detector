FROM python:3.10-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Hugging Face Spaces runs on port 7860
EXPOSE 7860

# Run Flask on port 7860
CMD ["python", "app.py"]
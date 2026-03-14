FROM python:3.13-slim

WORKDIR /app

# Install Tailwind CSS standalone CLI
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/* \
    && curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-linux-x64 \
    && chmod +x tailwindcss-linux-x64 \
    && mv tailwindcss-linux-x64 /usr/local/bin/tailwindcss

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Build Tailwind CSS
RUN tailwindcss -i ./static/css/input.css -o ./static/css/tailwind.css --minify

EXPOSE 8080

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]

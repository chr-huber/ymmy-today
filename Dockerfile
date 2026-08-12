FROM python:3.13-slim

WORKDIR /app

# Install Tailwind CSS standalone CLI and supercronic.
# ffmpeg compresses TTS audio (Gemini returns raw PCM); without it the cache
# stores much larger WAV files instead.
# libvoikko1 + voikko-fi (~5 MB) lemmatise Finnish for tap-to-translate. The
# Python binding comes from pip, not apt, because apt's would target Debian's
# python3 rather than this image's.
RUN apt-get update && apt-get install -y curl ffmpeg libvoikko1 voikko-fi && rm -rf /var/lib/apt/lists/* \
    && curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-linux-x64 \
    && chmod +x tailwindcss-linux-x64 \
    && mv tailwindcss-linux-x64 /usr/local/bin/tailwindcss \
    && curl -sLO https://github.com/aptible/supercronic/releases/download/v0.2.33/supercronic-linux-amd64 \
    && chmod +x supercronic-linux-amd64 \
    && mv supercronic-linux-amd64 /usr/local/bin/supercronic

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Build Tailwind CSS
RUN tailwindcss -i ./static/css/input.css -o ./static/css/tailwind.css --minify

EXPOSE 8080

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]

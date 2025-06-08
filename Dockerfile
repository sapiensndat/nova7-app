FROM python:3.12-slim
WORKDIR /app
COPY nova7_backend/ .
COPY gcp-key.json .
RUN pip install flask flask-mail stripe google-cloud-storage python-dotenv flask-cors gunicorn
ENV FLASK_APP=index
ENV GCS_BUCKET_NAME=nova7-storage
ENV GOOGLE_APPLICATION_CREDENTIALS=/app/gcp-key.json
ENV STRIPE_SECRET_KEY=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
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "index:app"]

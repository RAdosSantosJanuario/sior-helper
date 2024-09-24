FROM python:3.12.6-slim

RUN adduser --disabled-password --gecos '' worker_user

WORKDIR /app

ENV TZ=Europe/Berlin
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Install Certbot and git
RUN apt-get update && \
    apt-get install -y certbot python3-certbot && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . /app

# Ensure appropriate permissions
RUN mkdir -p /app/instance && \
    chown -R worker_user:worker_user /app/instance

RUN mkdir -p scripts/framework && \
    mkdir -p script/framework/cache && \
    chown -R worker_user:worker_user scripts/framework && \
    chown -R worker_user:worker_user scripts/framework/cache


# Switch to the non-root user
USER worker_user

# Expose ports for HTTP and the Flask app
EXPOSE 80 5000

# Command to run the application
CMD ["gunicorn", "-w 4", "-b", "0.0.0.0:5000", "app:app"]
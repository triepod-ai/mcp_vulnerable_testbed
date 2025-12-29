# ⚠️  WARNING: INTENTIONALLY VULNERABLE DOCKER IMAGE
# FOR SECURITY TESTING PURPOSES ONLY
# DO NOT USE IN PRODUCTION

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY src/ /app/src/

# Install Python dependencies
RUN pip install --no-cache-dir \
    "mcp[cli]>=1.8.0" \
    pydantic>=2.10.0 \
    httpx>=0.27.0 \
    uvicorn>=0.30.0 \
    requests>=2.31.0 \
    jinja2>=3.1.0

# Create logs directory
RUN mkdir -p /app/logs

# Set Python path
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# ⚠️  Security warning on startup
RUN echo '#!/bin/bash\n\
echo ""\n\
echo "⚠️  ⚠️  ⚠️  WARNING ⚠️  ⚠️  ⚠️"\n\
echo "This container is INTENTIONALLY VULNERABLE"\n\
echo "FOR TESTING SECURITY ASSESSMENT TOOLS ONLY"\n\
echo "DO NOT USE IN PRODUCTION"\n\
echo "⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️"\n\
echo ""\n\
exec "$@"' > /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

# Run FastMCP server in stdio mode
# Server will wait for input from docker exec -i
CMD ["python3", "-u", "src/server.py"]

# Expose HTTP port (for future HTTP transport support)
EXPOSE 10900

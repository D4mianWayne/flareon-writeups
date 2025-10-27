# Use the official Python 3.12 slim image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# 1. Update system packages, install 'build-essential', and clean up.
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 2. Install Python packages including the utility and uncompyle6
RUN pip install emoji cowsay pyjokes art arc4 uncompyle6 --break-system-packages

# Copy the Python script (solve.py is assumed to be the script that generates the .pyc)
COPY solve2.py .

# Copy the shell script that will orchestrate the execution and decompression
COPY run_decompile.sh .

# Set the command to execute the shell script
CMD ["/bin/bash", "run_decompile.sh"]
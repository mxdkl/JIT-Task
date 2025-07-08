FROM docker.io/node:latest

WORKDIR /app

COPY ./src .
COPY ./requirements.txt .

RUN apt-get update && \
apt-get install -y python3 python3-pip

RUN pip3 install -r requirements.txt --break-system-packages

CMD ["python3", "main.py"]

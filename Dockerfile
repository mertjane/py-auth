FROM python:3.12.3-alpine

WORKDIR /app

COPY . /app/

RUN python3 -m pip install -r requirements.txt

CMD flask run --host 0.0.0.0

EXPOSE 5000
FROM python:3.9-alpine

RUN mkdir /app
WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY static static
COPY templates templates
COPY app.py app.py

COPY flag.txt /flag.txt

CMD [ "python", "app.py" ]
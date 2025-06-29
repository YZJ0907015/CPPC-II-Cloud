FROM python:3.13-slim

COPY . .

RUN pip install -r requirements.txt

EXPOSE 1653

CMD ["python3","src/server.py"] 
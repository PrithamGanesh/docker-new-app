# Python Docker Demo

Simple Flask app running inside Docker.

## Logging
The app now creates `logs/` and writes:
- `logs/requests.log`: one entry for every incoming request
- `logs/errors.log`: unhandled exceptions with traceback
- `logs/suspicious.log`: suspicious payload/signature matches and abnormal request rate

## Run locally
docker build -t python-docker-demo .
docker run -p 5000:5000 python-docker-demo

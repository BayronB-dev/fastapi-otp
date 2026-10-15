web: gunicorn app.main:app -k uvicorn_worker.UvicornWorker -w 1 --bind 0.0.0.0:$PORT --access-logfile -

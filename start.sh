#!/bin/bash
exec gunicorn -k geventwebsocket.gunicorn.workers.GeventWebSocketWorker -w 1 --timeout 120 app:app -b 0.0.0.0:$PORT --error-logfile -
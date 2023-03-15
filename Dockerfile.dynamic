FROM telegraf:1.24.4-alpine

# enable python + install deps
RUN apk add --update --no-cache python3 py3-pip postgresql14-client libpq-dev
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

# upload script
COPY telegraf_daemon_config.py /app/telegraf_daemon_config.py


ENTRYPOINT [ "/app/telegraf_daemon_config.py" ]

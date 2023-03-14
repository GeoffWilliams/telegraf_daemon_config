FROM telegraf:1.24.4-alpine

# upload script + deps list
COPY telegraf_daemon_config.py /app/telegraf_daemon_config
COPY requirements.txt /app/requirements.txt

# enable python + install deps
RUN apk add --update --no-cache python3 py3-pip
RUN pip install -r /app/requirements.txt

FROM python:3-slim

RUN apt-get update && apt-get install libssl-dev netcat -y && rm -rf /var/lib/apt/lists/*

RUN easy_install pip
RUN pip3 install flask
RUN pip3 install cryptography

ADD Main /opt/cryptoengine
ADD utils /opt/cryptoengine/utils

CMD [ "python3", "/opt/cryptoengine/run.py" ]






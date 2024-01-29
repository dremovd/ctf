FROM python:3.10-slim
WORKDIR /usr/src/app
COPY requirements.txt /usr/src/app
RUN pip install --trusted-host pypi.python.org -r requirements.txt
COPY . /usr/src/app
RUN mkdir -p /service_root

ENTRYPOINT ["python", "analyzer.py"]

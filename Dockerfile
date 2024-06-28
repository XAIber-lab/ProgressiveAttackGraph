FROM python:3.10
WORKDIR /docker_steering
COPY requirements.txt .
RUN pip install -r requirements.txt
RUN pip install pybind11
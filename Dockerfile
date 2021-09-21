FROM python:3.6.1-alpine
WORKDIR /Zhiffy
ADD . /Zhiffy
RUN pip install -r requirements.txt
EXPOSE 5001
CMD ["python", "application.py"]
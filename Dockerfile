FROM python:3.8
WORKDIR /app
ADD ./app /app
RUN python -m pip install --upgrade pip
RUN pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
EXPOSE 443
CMD ["python","app.py"]
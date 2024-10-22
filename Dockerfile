FROM python
COPY app.yml .
COPY . .
RUN pip install -r requirements.txt
CMD [ "flask", "run" ]
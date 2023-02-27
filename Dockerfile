FROM python AS build

WORKDIR /app
ADD ./src /app
ADD ./requirements.txt /app/requirements.txt

RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install pyinstaller && \
    pyinstaller ./main.py -F

FROM gcr.io/distroless/python3

WORKDIR /app
COPY --from=build /app/dist/main /app/main

ENTRYPOINT ["/app/main"]
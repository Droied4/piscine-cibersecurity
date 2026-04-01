FROM alpine:3.2

RUN apt-get update -qq && apt-get install -y build-essential
RUN mkdir /app
WORKDIR /app
COPY ./infection /app/

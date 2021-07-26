FROM node:10.13-alpine

WORKDIR /home
COPY . .
ENV TZ Asia/Seoul

RUN npm install
CMD npm run test

FROM node:22-bookworm-slim AS frontend-build

WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build


FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RENDER=true

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python deploy/build_demo_db.py

COPY --from=frontend-build /app/frontend/dist /app/frontend/dist

EXPOSE 10000

CMD ["python", "run_api.py"]

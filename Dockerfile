FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data
WORKDIR /app
RUN groupadd --gid 10001 analyzer && useradd --uid 10001 --gid analyzer --no-create-home analyzer \
    && mkdir /data && chown analyzer:analyzer /data
COPY --chown=analyzer:analyzer app /app/app
USER 10001:10001
CMD ["python", "-m", "app.main"]

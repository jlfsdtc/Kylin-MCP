FROM python:3.11-slim
WORKDIR /kylin-mcp
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . /kylin-mcp
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "kylin_mcp.main:app", "--host", "0.0.0.0", "--port", "8000"]

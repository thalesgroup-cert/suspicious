#################################################
#                                               #
#    DOCKERFILE TEMPLATE EMAIL FEEDER SERVICE   #
#                                               #
#################################################

# Multi-stage build for dependencies
FROM python AS builder

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG PATH_TO

ENV HTTP_PROXY=${HTTP_PROXY}
ENV HTTPS_PROXY=${HTTPS_PROXY}
ENV NO_PROXY=${NO_PROXY}
ENV PATH_TO=${PATH_TO}


# set working directory
WORKDIR /tmp/

# copy and install Python dependencies
COPY requirements.txt /tmp/
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /usr/src/app/wheels -r requirements.txt

# Final runtime stage
FROM python:slim

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG PATH_TO

ENV HTTP_PROXY=${HTTP_PROXY}
ENV HTTPS_PROXY=${HTTPS_PROXY}
ENV NO_PROXY=${NO_PROXY}
ENV PATH_TO=${PATH_TO}


RUN apt-get update  && apt-get install -y --no-install-recommends \
    curl \
    bash \
    libmariadb3 \
    logrotate \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# install dependencies
COPY --from=builder /usr/src/app/wheels /wheels
COPY --from=builder /tmp/requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache /wheels/*

COPY . .

# Configure runtime environment and unbuffered output
ENV PYTHONUNBUFFERED=1

#ENTRYPOINT ["/usr/local/bin/python", "-u", "main.py"]

# syntax=docker/dockerfile:1
FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    python3 ca-certificates coreutils libstdc++6 libpulse0 libnss3 libdbus-1-3 libx11-6 \
    libxcb1 libxcb-cursor0 libxcb-xinerama0 libxcb-keysyms1 libxcomposite1 libxcursor1 \
    libxdamage1 libxi6 libxrandr2 libxtst6 libxkbcommon0 libgl1 libegl1 libglu1-mesa \
    libvulkan1 libasound2 libfontconfig1 libfreetype6 libxkbfile1 libtcmalloc-minimal4 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*
COPY experiments/railway-android-software/download_sdk.py /tmp/download_sdk.py
COPY experiments/railway-android-software/trial.py /opt/zeus-trial.py
# Local builds can supply the managed proxy CA; Railway uses its normal roots.
RUN --mount=type=secret,id=ca_bundle \
    if [ -f /run/secrets/ca_bundle ]; then export SSL_CERT_FILE=/run/secrets/ca_bundle; fi; \
    timeout 480 python3 /tmp/download_sdk.py && rm /tmp/download_sdk.py
ENV ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk \
    PATH=/opt/android-sdk/emulator:/opt/android-sdk/platform-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CMD ["python3", "-u", "/opt/zeus-trial.py"]

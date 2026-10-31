# syntax=docker/dockerfile:1
FROM gradle:8.11.1-jdk17 AS keyboard
USER root
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip && rm -rf /var/lib/apt/lists/*
ENV ANDROID_HOME=/opt/android
WORKDIR /src
COPY AndroidLab/ime/ /src/
# The optional trust mounts are for managed build environments only. Session
# trust stores are removed in this same layer and never enter the final image.
RUN --mount=type=secret,id=proxy_ca --mount=type=secret,id=system_ca \
    set -eu; \
    if [ -f /run/secrets/proxy_ca ]; then \
      cp "$JAVA_HOME/lib/security/cacerts" /tmp/java-trust; \
      keytool -importcert -noprompt -alias zeus-build-proxy -file /run/secrets/proxy_ca -keystore /tmp/java-trust -storepass changeit; \
      export JAVA_TOOL_OPTIONS='-Djavax.net.ssl.trustStore=/tmp/java-trust -Djavax.net.ssl.trustStorePassword=changeit'; \
    fi; \
    if [ -f /run/secrets/system_ca ]; then export CURL_CA_BUNDLE=/run/secrets/system_ca; fi; \
    curl -fsSL https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -o /tmp/sdk.zip; \
    mkdir -p /opt/android/cmdline-tools; unzip -q /tmp/sdk.zip -d /opt/android/cmdline-tools; \
    mv /opt/android/cmdline-tools/cmdline-tools /opt/android/cmdline-tools/latest; \
    yes | /opt/android/cmdline-tools/latest/bin/sdkmanager --licenses >/dev/null; \
    /opt/android/cmdline-tools/latest/bin/sdkmanager 'platforms;android-35' 'build-tools;35.0.0' >/dev/null; \
    gradle --no-daemon :app:assembleDebug; rm -f /tmp/java-trust /tmp/sdk.zip

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends adb openjdk-17-jre-headless apksigner zipalign curl unzip ca-certificates fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* && useradd --uid 10002 --create-home zeus-apk
WORKDIR /opt/zeus
COPY Cloud/requirements.lock /opt/zeus/Cloud/requirements.lock
COPY AndroidLab/requirements.in /opt/zeus/AndroidLab/requirements.in
RUN --mount=type=secret,id=system_ca \
    if [ -f /run/secrets/system_ca ]; then export PIP_CERT=/run/secrets/system_ca; fi; \
    pip install --no-cache-dir -r AndroidLab/requirements.in
RUN --mount=type=secret,id=system_ca \
    set -eu; if [ -f /run/secrets/system_ca ]; then export CURL_CA_BUNDLE=/run/secrets/system_ca; fi; \
    curl -fsSL https://github.com/iBotPeaches/Apktool/releases/download/v2.11.1/apktool_2.11.1.jar -o /opt/zeus/apktool.jar; \
    echo '56d59c524fc764263ba8d345754d8daf55b1887818b15cd3b594f555d249e2db  /opt/zeus/apktool.jar' | sha256sum -c -; \
    curl -fsSL https://github.com/skylot/jadx/releases/download/v1.5.3/jadx-1.5.3.zip -o /tmp/jadx.zip; \
    echo '8280f3799c0273fe797a2bcd90258c943e451fd195f13d05400de5e6451d15ec  /tmp/jadx.zip' | sha256sum -c -; \
    unzip -q /tmp/jadx.zip -d /opt/jadx; rm /tmp/jadx.zip; \
    printf '#!/bin/sh\nexec java -Xmx1536m -jar /opt/zeus/apktool.jar "$@"\n' > /usr/local/bin/apktool; \
    chmod +x /usr/local/bin/apktool /opt/jadx/bin/jadx
ENV PATH="/opt/jadx/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ZEUS_ANDROID_BUILD_UID=10002
COPY AndroidLab/zeus_android /opt/zeus/zeus_android
COPY --from=keyboard /src/app/build/outputs/apk/debug/app-debug.apk /opt/zeus/ime.apk
COPY AndroidLab/entrypoint.sh /opt/zeus/entrypoint.sh
RUN chmod +x /opt/zeus/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/opt/zeus/entrypoint.sh"]

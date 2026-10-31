# Bounded Railway software-emulator trial

This experiment attempts an API29 x86_64 Android boot with **`-accel off`** and a512MiB guest. It does not turn the production Android lab into a Railway deployment. It exposes only `/health`; there is no public ADB or upload endpoint. It installs no personal APKs, receives no model/provider credentials, mounts no persistent volume, and exits after at most900seconds plus8seconds of forced cleanup. Child processes receive a minimal environment without the existing service's credentials.

The SDK is fetched directly from Google's stable emulator/platform-tools metadata and API29 default-image metadata. Pinned official archive lengths and checksums are verified before extraction. No Gradle or model is installed. The image uses normal TLS verification; a local build can mount the managed proxy CA as a BuildKit secret, which is not persisted in layers.

The Dockerfile is a reproducible local preflight image. On Railway the deployed fallback uses a Python image and a bounded inline bootstrap because the current API rejects the deprecated railway.json configuration field. The bootstrap installs only runtime libraries and verified SDK archives within the same900second overall deadline; it passes the remaining budget to the boot trial.

Build from the repository root:

```sh
docker build -f experiments/railway-android-software/Dockerfile -t zeus-software-trial .
```

Deploy only to the existing explicitly authorized `big-lama-origin` test service, with restart policyNEVER, sleep enabled and boundedCPU/RAM. Read deployment SUCCESS separately from the structured `boot_completed`/`finished` logs. A successful `/health` is not an Android boot. Preserve the prior service configuration, verify cleanup/zero running replicas, and return limits to the small idle probe after the trial. Do not provision or upgrade an account to make this experiment work.

On a successful boot the script opens Android Settings and checks an actual PNG screenshot, recording its size and SHA256. On failure it records the exit reason and bounded emulator-log tail. Software emulation performance is unproven until a measured boot succeeds; a15minute deadline is a bounded test, not proof that no longer boot could work.

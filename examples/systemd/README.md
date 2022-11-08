# Using a systemd timer

This directory contains 3 files

- `environment`: Environment file used by systemd when running the timer service. Update it as required.

- `letsgo.service`: A systemd unit file defining a service associated with a systemd timer service.

- `letsgo.timer`: A systemd unit file defining a timer service.

## Install the systemd timer

1. Create the `/etc/letsgo` directory:

```bash
sudo mkdir -p /etc/letsgo
```

2. Copy and edit the environment file into `/etc/letsgo/environment`

3. Create the service file into `/etc/systemd/system/letsgo.service`

4. Create the timer file into `/etc/systemd/system/letsgo.timer`

5. Reload systemd daemon:

```bash
sudo systemctl daemon-reload
```

6. Enable and start the timer:

```bash
sudo systemctl enable --now letsgo.service
```

7. Show and follow logs:

```bash
sudo journalctl -afu letsgo
```

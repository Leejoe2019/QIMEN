# QIMEN minimal-install migration (2026-11-23)

**Goal:** on RackNerd, keep exactly one installed executable (`/usr/local/bin/qimen-server`), one systemd service unit (`/etc/systemd/system/qimen.service`), and one private config (`/etc/qimen.json`). Use only numeric port **18443**. No application credentials from environment variables.

**Current staged state:** the new server executable and service unit have been installed, but the unit is **disabled/inactive** because migration of the old TLS private key and shared token into the protected config was blocked by execution safety checks. The old temporary test process is still active and must not be mistaken for the new systemd unit. It uses TCP 18443 and UDP 80, and the dev client is the old process with a 4 s timeout. Stop the test process only when ready to switch.

## Step 1 — Server config (run locally as root on RackNerd)

The old test credentials currently live inside `/root/qimen-work`. This script reads them **on the same machine**, does not print secrets and does not use any environment variable. Do not run it if you have intentionally removed that directory.

```bash
python3 - <<'PY'
import json, os
base='/root/qimen-work'
with open(base+'/token') as f: secret=f.read().strip()
with open(base+'/server.crt') as f: cert=f.read()
with open(base+'/server.key') as f: key=f.read()
conf={
  'listen':'0.0.0.0:18443',
  'udp_listen':'107.173.181.158:18443',
  'token':secret,
  'tls_certificate_pem':cert,
  'tls_private_key_pem':key,
  'dial_timeout':'12s'
}
path='/etc/qimen.json'
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,'w') as f:json.dump(conf,f,indent=2);f.write('\\n')
os.chmod(path,0o600)
print(path, 'created, mode', oct(os.stat(path).st_mode&0o777))
PY
```

**Note:** this reuses the original self-signed test certificate, which was generated for about 30 days on 2026-11-23. **Plan renewal before expiry in December 2026**, updating the embedded certificate and the dev's embedded trusted CA simultaneously. Do not put the private config or PEM key in GitHub or an artifact-sharing service.

## Step 2 — Client config (run locally as root on dev)

The dev already has a matching client token and trusted server certificate under `/root/qimen-work`.

```bash
python3 - <<'PY'
import json,os
base='/root/qimen-work'
with open(base+'/token') as f: secret=f.read().strip()
with open(base+'/server.crt') as f: cert=f.read()
conf={
  'listen':'127.0.0.1:1080',
  'http_listen':'127.0.0.1:1081',
  'servers':['107.173.181.158:18443'],
  'token':secret,
  'tls_ca_pem':cert,
  'probe_interval':'30s',
  'dial_timeout':'12s',
  'asym_udp_address':'107.173.181.158:18443'
}
fd=os.open('/etc/qimen-client.json',os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,'w') as f:json.dump(conf,f,indent=2);f.write('\\n')
os.chmod('/etc/qimen-client.json',0o600)
print('Client config saved without displaying credentials')
PY
```

## Step 3 — Controlled cutover

The server's legacy PID was `1281422` and dev's legacy client PID was `19088` at the last audit. **Recheck process identity** before sending signals; PID reuse can occur.

On RackNerd:

```bash
ps -p 1281422 -o pid,args
# Only after confirming this PID is the OLD /root/qimen-work/qimen-server:
kill 1281422
systemctl daemon-reload
systemctl enable --now qimen.service
systemctl status --no-pager qimen.service
ss -lntup | grep 18443
```

On dev:

```bash
ps -p 19088 -o pid,args
# Only after confirming this PID is the OLD /root/qimen-work/qimen-client:
kill 19088
systemctl daemon-reload
systemctl enable --now qimen-client.service
systemctl status --no-pager qimen-client.service

curl --max-time 25 --proxy http://127.0.0.1:1081 http://example.com/
curl --max-time 25 --socks5-hostname 127.0.0.1:1080 https://example.com/
```

The service files specify `ExecStart=... --config ...`, and contain **no** `Environment=`, `EnvironmentFile=`, or secret-bearing CLI arguments. Runtime credentials are read from the private JSON file.

**Port semantics:** TCP 18443 and UDP 18443 have the same **numeric port**, but are separate sockets. For a literally single socket, edit server config to `"udp_listen":"-"`, which disables UDP tests.

## Step 4 — Clean old development material

Only after both systemd units are active and the proxy test succeeds:

```bash
# RackNerd: new binary and all credentials are now in /usr/local/bin and /etc.
rm -rf /root/qimen-work

# dev: remove only project-generated temporary files after checking the new client service
rm -rf /root/qimen-work
```

Keep `/root/PAT` **untouched**. Its permissions were previously tightened to `0600`, not its contents.

## Checks and limits

```bash
systemctl show -p ExecStart -p Environment qimen.service
systemctl is-enabled qimen.service
ss -lntup | grep 18443
find /etc -maxdepth 1 -name 'qimen*' -ls
stat -c '%a %n' /etc/qimen.json
journalctl -u qimen.service --no-pager -n 30
```

This migration changes only QIMEN-managed resources. It should not touch WARP, sing-box, TCP congestion-control routes, iptables/nftables, other network services, or their systemd units. It is a change in QIMEN startup, not a verified performance improvement.

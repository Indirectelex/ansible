# Install this documented infrastructure update

This archive is based on the project snapshot collected on August 16, 2026. It
adds explanations, guides, a service example, and documentation enforcement. It
does not intentionally change monitoring, dashboard, UniFi, storage, patch, or
ERPNext behaviour.

## 1. Protect the current working tree

Do not use Git reset or checkout because the repository already contains
valuable uncommitted dashboard and monitoring work.

```bash
cd "$HOME/infrastructure/ansible" || exit 1

backup_dir="$HOME/infrastructure-ansible-before-teacher-notes-$(date +%Y%m%d-%H%M%S)"
cp -a . "$backup_dir"
printf 'Backup: %s\n' "$backup_dir"
```

## 2. Extract the update

Substitute the actual downloaded archive name:

```bash
cd "$HOME/infrastructure/ansible" || exit 1
tar -xzf "$HOME/Downloads/hackwell-infrastructure-teacher-notes.tar.gz" -C .
```

The archive does not contain `.git`, secrets, Python caches, or the temporary
audit metadata directory.

## 3. Validate before publishing

```bash
cd "$HOME/infrastructure/ansible" || exit 1

python3 -m unittest discover -s tests -v
python3 -m py_compile \
  dashboard/server.py \
  roles/health_check/filter_plugins/*.py
node --check dashboard/assets/dashboard.js
python3 -m json.tool dashboard/assets/dashboard-topology.json >/dev/null
ansible-playbook --syntax-check playbooks/health-check.yml
ansible-playbook --syntax-check playbooks/security-update.yml
```

## 4. Publish source comments into the served copies

This step refreshes reports and copies the documented interface source into the
served `reports/` web root:

```bash
ansible-playbook playbooks/health-check.yml
```

No systemd change is required if the installed service already launches
`dashboard/server.py` with `reports/` as its web root.

## 5. Confirm the live boundaries

```bash
systemctl --user status hackwell-dashboard.service --no-pager -l
curl --fail --silent --show-error http://127.0.0.1:8088/manifest.json >/dev/null
curl --fail --silent --show-error http://127.0.0.1:8088/api/health-check/status
curl --silent --show-error http://127.0.0.1:8088/api/unifi/summary
```

Then force-refresh <http://127.0.0.1:8088/> and verify both `Datacenter` and
`Network` remain present.

## 6. Review and commit

```bash
git status --short
git diff --check
```

Review the existing uncommitted work together with this documentation update;
do not assume every pre-existing modification belongs to this package.

## Rollback

If extraction produces an unexpected result, stop before running a mutating
playbook and restore from the printed backup directory:

```bash
cd "$HOME/infrastructure/ansible" || exit 1
cp -a "$HOME/infrastructure-ansible-before-teacher-notes-YYYYMMDD-HHMMSS/." .
```

# Updates

DockScan never updates itself automatically. Updates require an explicit immutable release tag or commit.

## Check releases

```bash
dockscan update --check
```

## Apply a pinned update

```bash
sudo dockscan update --apply --ref v0.1.1
```

For releases with a published and trusted Git signing key:

```bash
sudo dockscan update --apply --ref v0.1.1 --verify-tag
```

The updater clones the selected HTTPS Git ref to a temporary directory, runs its local `install.sh`, and removes the temporary checkout. It rejects `main`, `master`, and `HEAD`.

## Manual/older-system update script

Download and retain `scripts/update-linux.sh`, then run:

```bash
sudo bash update-linux.sh --ref v0.1.1
```

Or host it and run a pinned release version:

```bash
curl -fsSL https://raw.githubusercontent.com/Danng-Dev/DockScan/v0.1.1/scripts/update-linux.sh | sudo bash -s -- --ref v0.1.1
```

Verify package manager, Python, Git, and systemd compatibility in a staging host first. Back up `/etc/dockscan`, private keys, token files, recovery kits, and evidence bundles before upgrading.

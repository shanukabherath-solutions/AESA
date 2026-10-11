Helper scripts for operating the sandbox image.

* `smoke.sh` runs the isolation checks against a built image (non-root, no network, read-only root, no host mounts).
* `verify-trivy.sh` builds the image and proves `trivy fs` works under the exact production restrictions (read-only root, no network, UID 10001, no capabilities, tmpfs `/tmp`) against the baked DB.
* `trivy-wrapper.sh` is installed in the image as `/usr/local/bin/trivy` (see the comments in the script).

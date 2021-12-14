# Lacework Auto Scanner

This project aims to make it easy to trigger vulnerability assessments for active containers that have integrated container registries within Lacework.

## How It Works

The default "look-back" period is 1 day, but can be augmented with the `--days <num_of_days>` or `--hours <num_of_hours>` arguments.

1. The script will download a report of all scanned containers for the "look-back" period. Containers that have already been scanned will be skipped by default. This can be overwritten with the `--rescan` flag.
2. The script will enumerate all integrated container registries, gathering the domains that can be scanned. This can be overwritten with the `--registry <registry_domain>` argument.
3. The script will run an LQL query against the specified Lacework account to gather distinct container repository/tag combinations that have run in the environment over the "look-back" period for the integrated domains.
4. The script will then issue container scan requests over the Lacework API for the containers.

## How To Run

The easiest way to run:

> `docker run -v ~/.lacework.toml:/home/user/.lacework.toml alannix/container-auto-scan`

This will mount your Lacework CLI credentials into the container and execute the scan on the default profile. You can, of course, pass in a different profile:

> `docker run -v ~/.lacework.toml:/home/user/.lacework.toml alannix/container-auto-scan -p <profile>`

Or you can provide credentials using the `--account`, `--subaccount`, `--api-key`, `--api-secret` arguments.

The script can also read the standard Lacework CLI environment variables for authentication.

## Known Issues

- Due to Lacework API limitations, only 400 containers can be scanned in a single hour.
- Due to Lacework API limitations, only 5000 scanned container images (for de-duplication) will get returned.
- Due to Lacework API limitations, only 5000 container repo/tag combinations will get returned.

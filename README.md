# Lacework Auto Scanner

![Build Status](https://github.com/lacework-dev/container-auto-scan/actions/workflows/python-test.yml/badge.svg)
![Docker Pulls](https://img.shields.io/docker/pulls/alannix/container-auto-scan)

The aim of this project is to make it simple to trigger vulnerability assessments for containers which are active and have integrated container registries in Lacework.

## How It Works

1. The script will download a report of all scanned containers a defined "look-back" period. Containers that have already been scanned will be skipped by default. This can be overwritten with the `--rescan` flag.
2. The script will enumerate all integrated container registries, gathering the domains that can be scanned. This can be overwritten with the `--registry <registry_domain>` argument.
3. The script will run a query against the specified Lacework account to gather distinct container repository/tag combinations that have run in the environment over the "look-back" period for the integrated domains.
4. The script will then issue container scan requests for the un-scanned active containers via the Lacework API.
5. If using the Inline Scanner option, the script will try to scan active containers without container registry integrations using the Inline Scanner.

The default "look-back" period is 1 day, but can be augmented with the `--days <num_of_days>` or `--hours <num_of_hours>` arguments.

## How To Run

### Local Execution

The easiest way to run this script is by executing it as a container using Lacework API credentials provided from your Lacework CLI configuration:

```bash
docker run -v ~/.lacework.toml:/home/user/.lacework.toml alannix/container-auto-scan
```

This will mount your Lacework CLI credentials into the container and execute the scan on the default profile. You can, of course, pass in a different profile with the `-p <profile>` argument as outlined [here](#user-content-arguments). Or you can provide credentials using the `--account`, `--subaccount`, `--api-key`, `--api-secret` arguments.

The script can also read the standard Lacework CLI environment variables for authentication as outlined [here](#user-content-environment-variables).

If cloning this repository, rather than using a container, you can run the script with the following usage:

```bash
usage: ./auto-scan.py [-h] [--account ACCOUNT] [--subaccount SUBACCOUNT] [--api-key API_KEY] [--api-secret API_SECRET] [-p PROFILE] [--proxy-scanner PROXY_SCANNER] [--days DAYS] [--hours HOURS] [--registry REGISTRY] [--rescan] [--list-only] [--inline-scanner] [--inline-scanner-path INLINE_SCANNER_PATH] [--inline-scanner-access-token INLINE_SCANNER_ACCESS_TOKEN] [--inline-scanner-only] [-d] [--debug]
```

### Inline Scanner Based Scans

As of version `0.3` of this script, scans now support the use of the Lacework Inline Scanner for container assessments. The use case for this is to scan containers which do _not_ have an integrated container registry in a Lacework account. This will also allow scanning of publicly accessible images, as the Inline Scanner will pull them through the local Docker daemon.

The new Inline Scanner functionality can be leveraged either by running the `auto_scan.py` script with the `--inline-scanner` argument on a machine with the Inline Scanner installed, or it can be run with a new Docker-in-Docker enabled container.

When executing in this mode, the script will attempt to scan as many container repositories as possible with the Platform scanner, and fall back to the Inline scanner only when required. This behavior can be augmented with the `--inline-scanner-only` argument which will force all scans through the Inline Scanner.

Due to permissions and dependency requirements for Docker-in-Docker, a new container image has been created (`container-auto-scan-inline`) which runs as the `root` user, and installs the necessary components. This also means that the image is much larger than the `container-auto-scan` image. Both images will follow the same release cycle and tagging conventions.

In order to run the Docker-in-Docker container, you'll execute the following:

```bash
docker run -v ~/.lacework.toml:/root/.lacework.toml -v /var/run/docker.sock:/var/run/docker.sock alannix/container-auto-scan-inline --inline-scanner-access-token <SCANNER_ACCESS_TOKEN_HERE>
```

#### Things to Note

- The Inline Scanner based container repository is named `container-auto-scan-inline` instead of `container-auto-scan`
- The Inline Scanner based container runs as `root` rather than `user`
  - As a result, the `lacework.toml` file is mounted in `/root/` rather than `/home/user/`
- The Inline Scanner based scans require an access token be provided in one of two ways:
  - The `--inline-scanner-access-token` argument
  - The `LW_ACCESS_TOKEN` environment variable while setting the `--inline-scanner` argument
- The Inline Scanner is currently limited to [60 scans per hour](https://docs.lacework.com/integrate-inline-scanner#scanning-quotas).

### Kubernetes Manifest

If you wish to run this script continuously, there is an example Kubernetes manifest in the [manifests](manifests/) directory which will store your Lacework API credentials as a Kubernetes Secret and then run the container in a Deployment with the `-d` flag to execute it as a daemon.

## Arguments

| short | long                            | default | help                                                                                                                                                                             |
| :---- | :------------------------------ | :------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-h`  | `--help`                        |         | show this help message and exit                                                                                                                                                  |
|       | `--account`                     | `None`  | The Lacework account to use                                                                                                                                                      |
|       | `--subaccount`                  | `None`  | The Lacework sub-account to use                                                                                                                                                  |
|       | `--api-key`                     | `None`  | The Lacework API key to use                                                                                                                                                      |
|       | `--api-secret`                  | `None`  | The Lacework API secret to use                                                                                                                                                   |
| `-p`  | `--profile`                     | `None`  | The Lacework CLI profile to use                                                                                                                                                  |
|       | `--proxy-scanner`               | `None`  | The address of a Lacework proxy scanner: http(s)://[address]:[port]                                                                                                              |
|       | `--days`                        | `None`  | The number of days in which to search for active containers                                                                                                                      |
|       | `--hours`                       | `0`     | The number of hours in which to search for active containers                                                                                                                     |
|       | `--registry`                    | `None`  | The container registry domain(s) for which to issue scans (comma separated)                                                                                                      |
|       | `--rescan`                      |         | Issue scan requests for previously scanned containers                                                                                                                            |
|       | `--list-only`                   |         | Only list active containers for integrated/specified registries (no scans)                                                                                                       |
|       | `--inline-scanner`              | `None`  | Use local Inline Scanner to evaluate images rather than Lacework platform (will attempt to scan images regardless of registry integration status)                                |
|       | `--inline-scanner-path`         | `None`  | Path to the Inline Scanner executable (default: lw-scanner expected on path)                                                                                                     |
|       | `--inline-scanner-access-token` | `None`  | Inline Scanner authentication token (in production environments it is recommended to use the `--inline-scanner` argument paried with the `LW_ACCESS_TOKEN` environment variable) |
|       | `--inline-scanner-only`         |         | Use Inline Scanner exculsively (default: use platform scans with inline scanner for unconfigured registries)                                                                     |
|       | `--org-level`                   |         | Iterate through each Account in an Organization                                                                                                                                  |
| `-d`  | `--daemon`                      |         | Run the scanner as a daemon (executes every 20 minutes)                                                                                                                          |
|       | `--debug`                       |         | Enable debug logging                                                                                                                                                             |

## Environment Variables

### Lacework API

| Environment Variable | Description                                                          | Required |
| -------------------- | -------------------------------------------------------------------- | :------: |
| `LW_PROFILE`         | Lacework CLI profile to use (configured at ~/.lacework.toml)         |    N     |
| `LW_ACCOUNT`         | Lacework account/organization domain (i.e. `<account>`.lacework.net) |    N     |
| `LW_SUBACCOUNT`      | Lacework sub-account                                                 |    N     |
| `LW_API_KEY`         | Lacework API Access Key                                              |    N     |
| `LW_API_SECRET`      | Lacework API Access Secret                                           |    N     |

## Lacework Inline Scanner

| Environment Variable | Description                                  | Required |
| -------------------- | -------------------------------------------- | :------: |
| `LW_ACCESS_TOKEN`    | Lacework Inline Scanner authentication token |    N     |

## Known Issues

- Due to Lacework API limitations, only 400 containers can be scanned in a single hour.
- Due to Lacework API limitations, only 5000 scanned container images (for de-duplication) will get returned.
- Due to Lacework API limitations, only 5000 container repo/tag combinations will get returned per registry.

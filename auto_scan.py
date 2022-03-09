#!/usr/bin/env python

import argparse
import json
import logging
import os
import time
import subprocess

import requests

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from laceworksdk import LaceworkClient

FAILED_SCAN_CACHE = 'failed_scan_cache.json'
FAILED_SCAN_CACHE_REASONS = [
    'ERROR: Unsupported base image OS.',
    'ERROR: Error while scanning image: Docker daemon is not running locally.'
]
INTERVAL = 1200
PAGINATION_MAX = 5000
WORKER_THREADS = 10


def build_container_assessment_cache(lw_client, start_time, end_time):
    print(f'Fetching container assessments since "{start_time}"...')

    scanned_containers = lw_client.vulnerabilities.get_container_assessments_by_date(
        start_time=start_time,
        end_time=end_time
    )

    num_returned = len(scanned_containers.get('data', {}))
    if num_returned == PAGINATION_MAX:
        logging.warning(f'Warning! The maximum number of container assessments ({PAGINATION_MAX}) was returned.')
    print(f'Previously Assessed Container Count: {num_returned}')

    print('Building container assessment cache...')

    scanned_container_cache = {}

    for scanned_container in scanned_containers.get('data', {}):
        if scanned_container['IMAGE_REPO'] not in scanned_container_cache.keys():
            scanned_container_cache[scanned_container['IMAGE_REPO']] = scanned_container['IMAGE_TAGS']
        else:
            scanned_container_cache[scanned_container['IMAGE_REPO']] += scanned_container['IMAGE_TAGS']

    return scanned_container_cache


def build_container_query(registry=None):

    query_text = 'ContainersByRegistry { source { LW_HE_CONTAINERS }'
    if registry is not None:
        query_text += f" filter {{ starts_with(REPO, '{registry}') }}"
    query_text += ' return distinct {REPO, TAG} }'

    logging.debug(f'LQL Query is: {query_text}')

    return query_text


def get_container_registry_domains(lw_client):
    print('Fetching container registry domains...')

    container_registries = lw_client.container_registries.get()

    container_registry_domains = []

    for container_registry in container_registries['data']:
        container_registry_domain = container_registry['data'].get('registryDomain', None)
        if container_registry['enabled'] and container_registry_domain:
            if container_registry_domain == 'index.docker.io':
                container_registry_domain = 'docker.io'

            if container_registry_domain not in container_registry_domains:
                container_registry_domains.append(container_registry_domain)

    print(f'Returned Container Domains: {container_registry_domains}')

    return container_registry_domains


def get_active_containers(lw_client, start_time, end_time, registry_domains=None):

    active_containers = []

    if registry_domains is not None:

        # Query for active containers for integrated registries
        for registry_domain in registry_domains:
            print(f'Fetching active containers for {registry_domain}...')

            response = lw_client.queries.execute(
                query_text=build_container_query(registry_domain),
                arguments={
                    'StartTimeRange': start_time,
                    'EndTimeRange': end_time,
                }
            )

            response_containers = response.get('data', [])

            num_returned = len(response_containers)
            if num_returned == PAGINATION_MAX:
                logging.warning(f'Warning! The maximum number of active containers ({PAGINATION_MAX}) was returned.')
            print(f'Found {num_returned} active containers for {registry_domain}...')

            active_containers += response_containers
    else:
        print('Fetching all active containers...')

        response = lw_client.queries.execute(
            query_text=build_container_query(),
            arguments={
                'StartTimeRange': start_time,
                'EndTimeRange': end_time,
            }
        )

        response_containers = response.get('data', [])

        num_returned = len(response_containers)
        if num_returned == PAGINATION_MAX:
            logging.warning(f'Warning! The maximum number of active containers ({PAGINATION_MAX}) was returned.')
        print(f'Found {num_returned} active containers...')

        active_containers += response_containers

    return active_containers


def initiate_inline_scan(container_registry, container_repository, container_tag, args,
                         access_token=None, account_name=None):
    scan_errors = []

    # Check failed scan cache
    qualified_repo = f'{container_registry}/{container_repository}'
    failed_scan_cache = load_failed_inline_scans()
    if qualified_repo in failed_scan_cache.keys():
        if container_tag in failed_scan_cache[qualified_repo].keys():
            print(f'Skipping {qualified_repo} with tag "{container_tag}" due to previous failure.')
            return scan_errors

    # Build the path for lw-scanner
    executable_path = args.inline_scanner_path if args.inline_scanner_path else 'lw-scanner'

    # Build the base command
    command = f'{executable_path} image evaluate {container_registry}/{container_repository} {container_tag}'

    # If an inline scanner access token is provided, use it
    # Otherwise we assume that the LW_ACCESS_TOKEN env var is set
    if access_token:
        command += f' --access-token {access_token}'

    # If an account name is provided, use it
    # Otherwise we assume that the LW_ACCOUNT_NAME env var is set
    if account_name:
        command += f' --account-name {account_name}'

    # Assume we want to save the results to Lacework - that's why we're doing this, right?
    command += ' --save'

    logging.debug(f'Running: {command}')
    split_command = command.split()
    output = subprocess.run(split_command, check=False, capture_output=True, text=True)

    if output.stderr:
        err = output.stderr.split('\n\n')[-1:][0].rstrip()
        err_message = {
            'container_registry': container_registry,
            'container_repository': container_repository,
            'container_tag': container_tag,
            'error_message': err
        }
        scan_errors.append(err_message)

        # Cache failure results for specific messages
        for error_substr in FAILED_SCAN_CACHE_REASONS:
            if error_substr in err:
                save_failed_inline_scan(qualified_repo, container_tag, err)

    logging.debug(output.stdout)

    return scan_errors


def load_failed_inline_scans():
    # If we have a stored scan cache, then use it
    # Otherwise create an empty one
    if os.path.isfile(FAILED_SCAN_CACHE):
        # Open the CONFIG_FILE and load it
        with open(FAILED_SCAN_CACHE, 'r') as failed_scan_cache:
            return json.loads(failed_scan_cache.read())
    else:
        return {}


def save_failed_inline_scan(qualified_repo, tag, reason):
    failed_scan_cache = load_failed_inline_scans()

    if qualified_repo not in failed_scan_cache.keys():
        failed_scan_cache[qualified_repo] = {tag: reason}
    else:
        failed_scan_cache[qualified_repo][tag] = reason

    with open(FAILED_SCAN_CACHE, 'w') as output_file:
        json.dump(failed_scan_cache, output_file, indent=2)


def initiate_platform_scan(lw_client, container_registry, container_repository, container_tag):

    try:
        lw_client.vulnerabilities.initiate_container_scan(
            container_registry,
            container_repository,
            container_tag
        )
    except Exception as e:
        message = f'Failed to scan container {container_registry}/{container_repository} with tag ' \
                  f'"{container_tag}". Error: {e}'
        logging.warning(message)


def initiate_proxy_scan(session, proxy_scanner_addr, container_registry, container_repository, container_tag):

    try:
        json = {
            'registry': container_registry,
            'image_name': container_repository,
            'tag': container_tag
        }

        response = session.post(f'{proxy_scanner_addr}/v1/scan', json=json)
        response.raise_for_status()
    except Exception as e:
        message = f'Failed to scan container {container_registry}/{container_repository} with tag ' \
                  f'"{container_tag}". Error: {e}'
        logging.warning(message)


def list_containers(containers):
    for container in containers:
        if container['TAG'] == '':
            continue
        print(f'{container["REPO"]}:{container["TAG"]}')


def scan_containers(lw_client, container_scan_queue, container_registry_domains, scanned_container_cache, args):
    print(f'Container Count: {len(container_scan_queue)}')

    i = 1

    executor_tasks = []
    scan_errors = []

    with ThreadPoolExecutor(max_workers=WORKER_THREADS) as executor:
        for container in container_scan_queue:

            # Parse the container registry and repository
            container_registry, container_repository = container['REPO'].split('/', 1)
            if container['TAG'] == '':
                continue
            container_tag = container['TAG']

            if container_registry == 'docker.io':
                container_registry = 'index.docker.io'

            qualified_repo = f'{container_registry}/{container_repository}'

            # Skip if the container was previously scanned in the current window
            if qualified_repo in scanned_container_cache.keys():
                if container_tag in scanned_container_cache[qualified_repo]:
                    print(f'Skipping previously scanned {qualified_repo} with tag "{container_tag}"')
                    continue

            scan_msg = f'Scanning {container_registry}/{container_repository} with tag "{container_tag}" ({i}) '

            if args.inline_scanner and (args.inline_scanner_only or container_registry not in container_registry_domains):
                account_name = lw_client._account

                scan_msg += '(Inline Scanner)'
                print(scan_msg)

                executor_tasks.append(executor.submit(
                    initiate_inline_scan, container_registry, container_repository, container_tag,
                    args, access_token=args.inline_scanner_access_token, account_name=account_name
                ))

            elif args.proxy_scanner:
                scan_msg += '(Proxy Scanner)'
                print(scan_msg)

                session = requests.Session()
                executor_tasks.append(executor.submit(
                    initiate_proxy_scan, session, args.proxy_scanner,
                    container_registry, container_repository, container_tag
                ))

            else:
                scan_msg += '(Platform Scanner)'
                print(scan_msg)

                executor_tasks.append(executor.submit(
                    initiate_platform_scan, lw_client,
                    container_registry, container_repository, container_tag
                ))

            i += 1

        for task in as_completed(executor_tasks):
            result = task.result()
            if result:
                for error in result:
                    scan_errors.append(error)

    if scan_errors:
        print("""\nImages erroring out on scan listed below.
        The most common cause of an image scan failure is that the base image is unsupported.
        For a list of supported base images, see: https://docs.lacework.com/container-image-support \n""")
        for error in scan_errors:
            logging.error(error)


def main(args):

    try:
        lw_client = LaceworkClient(
            account=args.account,
            subaccount=args.subaccount,
            api_key=args.api_key,
            api_secret=args.api_secret,
            profile=args.profile
        )
    except Exception:
        raise

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    if args.days:
        days_back = args.days
    else:
        days_back = 1

    # Build start/end times
    current_time = datetime.now(timezone.utc)
    start_time = current_time - timedelta(hours=args.hours, days=days_back)
    start_time = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time = current_time
    end_time = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    # If rescanning, scan all containers - otherwise, skip already assessed containers
    if args.rescan:
        scanned_container_cache = {}
    else:
        scanned_container_cache = build_container_assessment_cache(lw_client, start_time, end_time)

    # If a registry is specified, use that
    # Otherwise, scan containers from all integrated domains
    if args.registry:
        container_registry_domains = [x.strip() for x in str(args.registry).split(',')]
    else:
        container_registry_domains = get_container_registry_domains(lw_client)

    # Inline scanner usage doesn't need to lookup registries
    # However, we should honor them if manually entered
    if args.inline_scanner:
        if args.registry:
            container_scan_queue = get_active_containers(lw_client, start_time, end_time, container_registry_domains)
        else:
            container_scan_queue = get_active_containers(lw_client, start_time, end_time)
    else:
        # Query for active containers across registries
        container_scan_queue = get_active_containers(lw_client, start_time, end_time, container_registry_domains)

    if args.list_only:
        list_containers(container_scan_queue)
    else:
        # Scan all the containers
        scan_containers(lw_client, container_scan_queue, container_registry_domains, scanned_container_cache, args)


if __name__ == '__main__':
    # Set up an argument parser
    parser = argparse.ArgumentParser(
        description='A script to automatically issue container vulnerability scans to Lacework based on running containers'
    )
    parser.add_argument(
        '--account',
        default=os.environ.get('LW_ACCOUNT', None),
        help='The Lacework account to use'
    )
    parser.add_argument(
        '--subaccount',
        default=os.environ.get('LW_SUBACCOUNT', None),
        help='The Lacework sub-account to use'
    )
    parser.add_argument(
        '--api-key',
        dest='api_key',
        default=os.environ.get('LW_API_KEY', None),
        help='The Lacework API key to use'
    )
    parser.add_argument(
        '--api-secret',
        dest='api_secret',
        default=os.environ.get('LW_API_SECRET', None),
        help='The Lacework API secret to use'
    )
    parser.add_argument(
        '-p', '--profile',
        default=os.environ.get('LW_PROFILE', None),
        help='The Lacework CLI profile to use'
    )
    parser.add_argument(
        '--proxy-scanner',
        default=None,
        type=str,
        help='The address of a Lacework proxy scanner: http(s)://[address]:[port]'
    )
    parser.add_argument(
        '--days',
        default=os.environ.get('LOOKBACK_DAYS', None),
        type=int,
        help='The number of days in which to search for active containers'
    )
    parser.add_argument(
        '--hours',
        default=0,
        type=int,
        help='The number of hours in which to search for active containers'
    )
    parser.add_argument(
        '--registry',
        help='The container registry domain(s) for which to issue scans (comma separated)'
    )
    parser.add_argument(
        '--rescan',
        dest='rescan',
        action='store_true',
        help='Issue scan requests for previously scanned containers'
    )
    parser.add_argument(
        '--list-only',
        dest='list_only',
        action='store_true',
        help='Only list active containers for integrated/specified registries (no scans)'
    )
    parser.add_argument(
        '--inline-scanner',
        default=os.environ.get('USE_INLINE_SCANNER', None),
        action='store_true',
        help="""Use local inline scanner to evaluate images rather than Lacework platform
        (will attempt to scan images regardless of registry integration status)"""
    )
    parser.add_argument(
        '--inline-scanner-path',
        type=str,
        help='Path to the lw-scanner executable (default value is lw-scanner expected on path)'
    )
    parser.add_argument(
        '--inline-scanner-access-token',
        default=None,
        type=str,
        help='Inline scanner authentication token'
    )
    parser.add_argument(
        '--inline-scanner-only',
        action='store_true',
        help='Use inline scanner exculsively. (default uses platform scans with inline scanner for unconfigured registries)'
    )
    parser.add_argument(
        '-d', '--daemon',
        action='store_true',
        help='Run the scanner as a daemon (executes every 20 minutes)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        default=os.environ.get('LW_DEBUG', False),
        help='Enable debug logging'
    )
    args = parser.parse_args()

    try:
        # If a daemon, create an infinite loop
        if args.daemon:
            while True:
                main(args)
                time.sleep(INTERVAL)
        else:
            main(args)
    except Exception as e:
        logging.error(e)
        parser.print_help()

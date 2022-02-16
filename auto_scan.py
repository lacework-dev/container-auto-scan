#!/usr/bin/env python

import argparse
import logging
import os
import time
import subprocess

import requests

from shellescape import quote
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from laceworksdk import LaceworkClient

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


def build_integrated_registry_query(registry):
    query_text = f"""ContainersByRegistry {{
        source {{
            LW_HE_CONTAINERS
        }}
        filter {{
            starts_with(REPO, '{registry}')
        }}
        return distinct {{REPO, TAG}}
    }}"""

    logging.debug(f'LQL Query is: {query_text}')

    return query_text


def get_active_containers_by_registry(lw_client, container_registry_domains, start_time, end_time):

    active_containers = []

    # Query for active containers across registries
    for container_registry_domain in container_registry_domains:
        print(f'Fetching active containers for {container_registry_domain}...')

        response = lw_client.queries.execute(
            evaluator_id='<<IMPLICIT>>',
            query_text=build_integrated_registry_query(container_registry_domain),
            arguments={
                'StartTimeRange': start_time,
                'EndTimeRange': end_time,
            }
        )

        response_containers = response.get('data', [])

        num_returned = len(response_containers)
        if num_returned == PAGINATION_MAX:
            logging.warning(f'Warning! The maximum number of active containers ({PAGINATION_MAX}) was returned.')
        print(f'Found {num_returned} active containers for {container_registry_domain}...')

        active_containers += response_containers

    return active_containers


def get_all_active_containers(lw_client, start_time, end_time):

    active_containers = []

    query_text = """AllContainers {
        source {
            LW_HE_CONTAINERS
        }
        return distinct {REPO, TAG}
    }"""

    # Query for active containers across registries
    logging.debug(f'LQL Query is: {query_text}')

    response = lw_client.queries.execute(
        evaluator_id='<<IMPLICIT>>',
        query_text=query_text,
        arguments={
            'StartTimeRange': start_time,
            'EndTimeRange': end_time,
        }
    )

    response_containers = response.get('data', [])

    num_returned = len(response_containers)
    # TODO: Handle pagination edge case
    if num_returned == PAGINATION_MAX:
        logging.warning(f'Warning! The maximum number of active containers ({PAGINATION_MAX}) was returned.')

    active_containers += response_containers

    logging.debug(f'active_containers: {active_containers}')

    return active_containers


def list_containers(containers):
    for container in containers:
        if container['TAG'] == '':
            continue
        print(f'{container["REPO"]}:{container["TAG"]}')


def initiate_container_scan(lw_client, container_registry, container_repository, container_tag):

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
                  f'{container_tag}". Error: {e}'
        logging.warning(message)


def scan_containers(lw_client, containers, scanned_container_cache, args):
    print(f'Container Count: {len(containers)}')

    i = 1

    executor_tasks = []
    with ThreadPoolExecutor(max_workers=WORKER_THREADS) as executor:
        scan_errors = []
        for container in containers:
            # Parse the container registry and repository
            # TODO: Edge case on repos with two+ levels of nesting...
            container_registry, container_repository = container['REPO'].split('/', 1)
            if container['TAG'] == '':
                continue
            container_tag = container['TAG']

            if container_registry == 'docker.io' and not args.use_inline_scanner:
                container_registry = 'index.docker.io'

            qualified_repo = f'{container_registry}/{container_repository}'

            # Skip if the container was previously scanned in the current window
            if qualified_repo in scanned_container_cache.keys():
                if container_tag in scanned_container_cache[qualified_repo]:
                    print(f'Skipping previously scanned {qualified_repo} with tag "{container_tag}"')
                    continue

            print(f'Scanning {container_registry}/{container_repository} with tag "{container_tag}" ({i})')

            if args.use_inline_scanner:
                # TODO: Could this use a ThreadPoolExecutor...idk

                # TODO: dedupe this code
                executable_path = 'lw-scanner'

                if args.path_to_inline_scanner:
                    executable_path = args.path_to_inline_scanner
                # -----------------------

                # TODO: We could try to pull this dynamically if we have the profile ?
                if args.inline_scanner_access_token:
                    command = f"""{executable_path} image evaluate {container_registry}/{container_repository} {container_tag}
                    --access-token {args.inline_scanner_access_token} --account {args.account} --save --quiet"""
                else:
                    command = f"""{executable_path} image evaluate {container_registry}/{container_repository} {container_tag}
                    --save --quiet"""
                command = command.format(quote(command))
                logging.debug(f'Running: {command}')
                split_command = command.split()
                output = subprocess.run(split_command, check=False, capture_output=True, text=True)
                if output.stderr:
                    scan_errors.append(f'Error scanning image: {container_registry}/{container_repository}:{container_tag}')
                else:
                    print(output.stdout)
                # TODO: Figure out how to persist these unsupported images so we don't continue to scan?
                # Or maybe this isn't actuallly a problem as we'll have a "bad" scan on the backend?

                # TODO: Figure out how / if we can scan by image_id for things like 'latest' tag

            elif args.proxy_scanner:
                session = requests.Session()
                executor_tasks.append(executor.submit(
                    initiate_proxy_scan, session, args.proxy_scanner, container_registry, container_repository, container_tag
                ))
            else:
                executor_tasks.append(executor.submit(
                    initiate_container_scan, lw_client, container_registry, container_repository, container_tag
                ))

            i += 1

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

    active_containers = []
    # inline scanner usage doesn't need to lookup registries that are configured
    if args.use_inline_scanner:
        # Removed check for whether inline scanner is installed due to guardrail findings 

        # TODO: Add more flags to support inline scanner flags -- assumed to save to platform and not eval policy right now
        active_containers = get_all_active_containers(lw_client, start_time, end_time)

    else:
        # If a registry is specified, use that - otherwise, scan containers from all integrated domains
        if args.registry:
            container_registry_domains = [x.strip() for x in str(args.registry).split(',')]
        else:
            container_registry_domains = get_container_registry_domains(lw_client)

        # Query for active containers across registries
        active_containers = get_active_containers_by_registry(lw_client, container_registry_domains, start_time, end_time)

    if args.list_only:
        list_containers(active_containers)
    else:
        # Scan all the containers
        scan_containers(lw_client, active_containers, scanned_container_cache, args)


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
        default=os.environ.get('LOOKBACK_DAYS', 0),
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
        '-d', '--daemon',
        action='store_true',
        help='Run the scanner as a daemon (executes every 20 minutes)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    parser.add_argument(
        '--use-inline-scanner',
        dest='use_inline_scanner',
        default=os.environ.get('USE_INLINE_SCANNER', None),
        action='store_true',
        help="""Use local inline scanner to evaluate images rather than Lacework platform
        (will attempt to scan images regardless of registry integration status)"""
    )
    parser.add_argument(
        '--path-to-inline-scanner',
        dest='path_to_inline_scanner',
        type=str,
        help='Path to the lw-scanner executable (default value is lw-scanner expected on path)'
    )
    parser.add_argument(
        '--inline-scanner-access-token',
        dest='inline_scanner_access_token',
        default=os.environ.get('LW_ACCESS_TOKEN', None),
        type=str,
        help='Inline scanner authentication token'
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

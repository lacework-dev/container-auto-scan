#!/usr/bin/env python

import argparse
import logging
import os

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from laceworksdk import LaceworkClient

PAGINATION_MAX = 5000
WORKER_THREADS = 10


def build_container_assessment_cache(lw_client):
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
        if container_registry_domain:
            container_registry_domains.append(container_registry_domain)

    print(f'Returned Container Domains: {container_registry_domains}')

    return container_registry_domains


def build_integrated_registries_query(registries):
    query_text = """ContainersByRegistry {
        source {
            LW_HE_CONTAINERS
        }
        filter {"""

    for registry in registries:
        query_text += f"starts_with(REPO, '{registry}') OR "
    query_text = query_text[:-4]

    query_text += """}
        return distinct {REPO, TAG}
        }
    """

    logging.debug(f'LQL Query is: {query_text}')

    return query_text


def get_active_containers(lw_client, container_registry_domains):

    # Query for active containers across registries
    response = lw_client.queries.execute(
        evaluator_id='<<IMPLICIT>>',
        query_text=build_integrated_registries_query(container_registry_domains),
        arguments={
            'StartTimeRange': start_time,
            'EndTimeRange': end_time,
        }
    )

    num_returned = len(response.get('data', {}))
    if num_returned == PAGINATION_MAX:
        logging.warning(f'Warning! The maximum number of active containers ({PAGINATION_MAX}) was returned.')
    print(f'Active Container Count: {num_returned}')

    return response


def initiate_container_scan(container_registry, container_repository, container_tag):
    try:
        lw_client.vulnerabilities.initiate_container_scan(
            container_registry,
            container_repository,
            container_tag
        )
    except Exception as e:
        message = f'Failed to scan container {container_registry}/{container_repository} with tag ' \
            f'{container_tag}". Error: {e}'
        logging.warning(message)


def scan_containers(containers, scanned_container_cache):
    print(f'Container Count: {len(containers)}')

    i = 1

    executor_tasks = []
    with ThreadPoolExecutor(max_workers=WORKER_THREADS) as executor:
        for container in containers:

            # Parse the container registry and repository
            container_registry, container_repository = container['REPO'].split('/', 1)

            # Skip if the container was previously scanned in the current window
            if container_repository in scanned_container_cache.keys():
                if container['TAG'] in scanned_container_cache[container_repository]:
                    print(f'Skipping previously scanned {container_repository} with tag "{container["TAG"]}"')
                    continue

            print(f'Scanning {container_registry}/{container_repository} with tag "{container["TAG"]}" ({i})')

            executor_tasks.append(executor.submit(
                initiate_container_scan, container_registry, container_repository, container['TAG']
            ))

            i += 1


if __name__ == '__main__':

    # Set up an argument parser
    parser = argparse.ArgumentParser(
        description='A script to automatically issue container vulnerability scans to Lacework based on running containers'
    )

    parser.add_argument('--account', default=os.environ.get('LW_ACCOUNT', None), help='The Lacework account')
    parser.add_argument('--subaccount', default=os.environ.get('LW_SUBACCOUNT', None), help='The Lacework sub-account')
    parser.add_argument('--api-key', dest='api_key', default=os.environ.get('LW_API_KEY', None), help='The Lacework API key')
    parser.add_argument(
        '--api-secret', dest='api_secret', default=os.environ.get('LW_API_SECRET', None), help='The Lacework API secret'
    )
    parser.add_argument('-p', '--profile', default=os.environ.get('LW_PROFILE', None), help='The Lacework CLI profile')
    parser.add_argument('--days', default=None, type=int, help='The number of days in which to search for active containers')
    parser.add_argument('--hours', default=0, type=int, help='The number of hours in which to search for active containers')
    parser.add_argument('--registry', help='The container registry domain for which to issue scans')
    parser.add_argument('--rescan', dest='rescan', action='store_true')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    try:
        lw_client = LaceworkClient(
            account=args.account,
            subaccount=args.subaccount,
            api_key=args.api_key,
            api_secret=args.api_secret,
            profile=args.profile
        )
    except Exception as e:
        logging.error(e)
        parser.print_help()
        exit()

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
        scanned_container_cache = build_container_assessment_cache(lw_client)

    # If a registry is specified, use that - otherwise, scan containers from all integrated domains
    if args.registry:
        container_registry_domains = [args.registry]
    else:
        container_registry_domains = get_container_registry_domains(lw_client)

    # Query for active containers across registries
    active_containers = get_active_containers(lw_client, container_registry_domains)

    # Scan all the containers
    scan_containers(active_containers.get('data', []), scanned_container_cache)

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
from laceworksdk.exceptions import ApiError, RateLimitError
from tabulate import tabulate

SCAN_CACHE_DIR = os.getenv('LW_SCANNER_DATA_DIR', 'cache')
FAILED_SCAN_CACHE = f'{SCAN_CACHE_DIR}/failed_scan_cache.json'
FAILED_SCAN_CACHE_REASONS = [
    'ERROR: Unsupported base image OS.',
    'ERROR: Error while scanning image: Docker daemon is not running locally.'
]
INTERVAL = 1200
PAGINATION_MAX = 5000
WORKER_THREADS = 10

logging.basicConfig(
    format='%(asctime)s %(name)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger('auto-scan')
logger.setLevel(os.getenv('LOG_LEVEL', logging.INFO))


def build_container_assessment_cache(lw_client, start_time, end_time):
    logger.info(f'Fetching container assessments since "{start_time}"...')

    scanned_containers = lw_client.vulnerabilities.get_container_assessments_by_date(
        start_time=start_time,
        end_time=end_time
    )

    logger.info('Building container assessment cache...')

    returned_containers = 0
    scanned_container_cache = {}

    for scanned_container in scanned_containers.get('data', []):

        registry = scanned_container['IMAGE_REGISTRY']
        repository = scanned_container['IMAGE_REPO']
        tags = scanned_container['IMAGE_TAGS']

        qualified_repo = f'{registry}/{repository}'

        if qualified_repo not in scanned_container_cache.keys():
            scanned_container_cache[qualified_repo] = tags
            returned_containers += len(tags)
        else:
            for tag in tags:
                if tag not in scanned_container_cache[qualified_repo]:
                    scanned_container_cache[qualified_repo].append(tag)
                    returned_containers += 1

    logger.info(f'Previously Assessed Container Count: {returned_containers}')
    logger.debug(json.dumps(scanned_container_cache, indent=4))

    return scanned_container_cache


def build_container_query(registry=None):

    query_text = '{ source { LW_HE_CONTAINERS }'
    if registry is not None:
        if registry == 'index.docker.io':
            registry = 'docker.io'
        query_text += f" filter {{ starts_with(REPO, '{registry}') }}"
    query_text += ' return distinct {REPO, TAG} }'

    logger.debug(f'LQL Query: {query_text}')

    return query_text


def build_scan_result(scanner_type, repository, tag, error=None):

    result_message = {
        'scanner_type': scanner_type,
        'repository': repository,
        'tag': tag,
        'error': error
    }

    return result_message


def get_container_registry_domains(lw_client):
    logger.info('Fetching container registry domains...')

    registries = lw_client.container_registries.get()

    registry_domains = []

    for registry in registries['data']:
        registry_domain = registry['data'].get('registryDomain', None)
        if registry['enabled'] and registry_domain:
            if registry_domain not in registry_domains:
                registry_domains.append(registry_domain)

    logger.info(f'Returned Container Domains: {registry_domains}')

    return registry_domains


def get_active_containers(lw_client, start_time, end_time, registry_domains=None):

    active_containers = []

    if registry_domains is not None:

        # Query for active containers for integrated registries
        for registry_domain in registry_domains:
            logger.info(f'Fetching active containers for {registry_domain}...')

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
                logger.warning(f'Warning! The maximum number of active containers ({PAGINATION_MAX}) was returned.')
            logger.info(f'Found {num_returned} active containers for {registry_domain}...')

            active_containers += response_containers
    else:
        logger.info('Fetching all active containers...')

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
            logger.warning(f'Warning! The maximum number of active containers ({PAGINATION_MAX}) was returned.')
        logger.info(f'Found {num_returned} active containers...')

        active_containers += response_containers

    return active_containers


def load_failed_scans():
    # If we have a stored scan cache, then use it
    # Otherwise create an empty one
    if os.path.isfile(FAILED_SCAN_CACHE):
        # Open the CONFIG_FILE and load it
        with open(FAILED_SCAN_CACHE, 'r') as failed_scan_cache:
            return json.loads(failed_scan_cache.read())
    else:
        return {}


def save_failed_scan(qualified_repo, tag, reason):
    failed_scan_cache = load_failed_scans()

    if qualified_repo not in failed_scan_cache.keys():
        failed_scan_cache[qualified_repo] = {tag: reason}
    else:
        failed_scan_cache[qualified_repo][tag] = reason

    with open(FAILED_SCAN_CACHE, 'w') as output_file:
        json.dump(failed_scan_cache, output_file, indent=2)


def initiate_inline_scan(registry, repository, tag, args,
                         access_token=None, account_name=None):

    error_message = None
    qualified_repo = f'{registry}/{repository}'

    # Build the path for lw-scanner
    executable_path = args.inline_scanner_path if args.inline_scanner_path else 'lw-scanner'

    # Build the base command
    command = f'{executable_path} image evaluate {qualified_repo} {tag}'

    # If an inline scanner access token is provided, use it
    # Otherwise we assume that the LW_ACCESS_TOKEN env var is set
    if access_token:
        command += f' --access-token {access_token}'

    # If an account name is provided, use it
    # Otherwise we assume that the LW_ACCOUNT_NAME env var is set
    if account_name:
        command += f' --account-name {account_name}'

    # Set the cache directory to local
    command += f' --data-directory {SCAN_CACHE_DIR}'

    # Assume we want to save the results to Lacework - that's why we're doing this, right?
    command += ' --save'

    logger.debug(f'Running: {command}')
    split_command = command.split()
    output = subprocess.run(split_command, check=False, capture_output=True, text=True)

    if output.stderr:
        error_message = output.stderr.split('\n\n')[-1:][0].rstrip()

        # Cache failure results for specific messages
        for error_substr in FAILED_SCAN_CACHE_REASONS:
            if error_substr in error_message:
                save_failed_scan(qualified_repo, tag, error_message)

    logger.debug(output.stdout)

    return build_scan_result('Inline', qualified_repo, tag, error_message)


def initiate_platform_scan(lw_client, registry, repository, tag):

    error_message = None
    qualified_repo = f'{registry}/{repository}'

    try:
        lw_client.vulnerabilities.initiate_container_scan(
            registry,
            repository,
            tag
        )
    except RateLimitError as e:
        error_message = f'Received rate limit response from Lacework. Exiting to prevent ' \
                        f'exasperating the issue. Error: {e}'
        logger.warning(error_message)
        os._exit(1)
    except ApiError as e:
        error_message = f'Failed to scan container {qualified_repo} with tag ' \
                        f'"{tag}". Error: {e}'
        logger.warning(error_message)
        if 400 <= e.status_code < 500:
            save_failed_scan(qualified_repo, tag, error_message)
    except Exception as e:
        error_message = f'Failed to scan container {qualified_repo} with tag ' \
                        f'"{tag}". Error: {e}'
        logger.warning(error_message)

    return build_scan_result('Platform', qualified_repo, tag, error_message)


def initiate_proxy_scan(session, proxy_scanner_addr, registry, repository, tag):

    error_message = None
    qualified_repo = f'{registry}/{repository}'

    try:
        json = {
            'registry': registry,
            'image_name': repository,
            'tag': tag
        }

        response = session.post(f'{proxy_scanner_addr}/v1/scan', json=json)
        response.raise_for_status()
    except Exception as e:
        error_message = f'Failed to scan container {qualified_repo} with tag ' \
                        f'"{tag}". Error: {e}'
        logger.warning(error_message)

    return build_scan_result('Proxy', qualified_repo, tag, error_message)


def list_containers(containers):
    for container in containers:
        if container['TAG'] == '':
            continue
        logger.info(f'{container["REPO"]}:{container["TAG"]}')


def parse_container_attributes(container):

    # Parse the container registry and repository
    registry, repository = container['REPO'].split('/', 1)
    tag = container['TAG']

    if registry == 'docker.io':
        registry = 'index.docker.io'

    return registry, repository, tag


def deduplicate_scans(lw_client, start_time, end_time, container_scan_queue, registry_domains):

    deduped_container_scan_queue = []

    # Load previously scanned containers
    failed_scan_cache = load_failed_scans()
    scanned_container_cache = build_container_assessment_cache(lw_client, start_time, end_time)

    skipped_containers = 0

    for container in container_scan_queue:

        registry, repository, tag = parse_container_attributes(container)

        qualified_repo = f'{registry}/{repository}'

        # Skip if the container was previously scanned in the current window
        if qualified_repo in scanned_container_cache.keys():
            if tag in scanned_container_cache[qualified_repo]:
                logger.info(f'Skipping previously scanned {qualified_repo} with tag "{tag}"')
                skipped_containers += 1
                continue

        # Skip if the container has a previously failed scan
        if qualified_repo in failed_scan_cache.keys():
            if tag in failed_scan_cache[qualified_repo].keys():
                logger.info(f'Skipping previously failed {qualified_repo} with tag "{tag}"')
                skipped_containers += 1
                continue

        deduped_container_scan_queue.append(container)

    logger.info(f'Skipped containers due to previous result: {skipped_containers}')

    return deduped_container_scan_queue


def create_scan_task(executor, executor_tasks, lw_client,
                     registry, repository, tag,
                     registry_domains, args, i):
    scan_msg = f'Scanning {registry}/{repository} with tag "{tag}" ({i}) '

    if (args.inline_scanner or args.inline_scanner_access_token) and \
       (args.inline_scanner_only or registry not in registry_domains):
        scan_msg += '(Inline Scanner)'
        logger.info(scan_msg)

        account_name = lw_client._account

        executor_tasks.append(executor.submit(
            initiate_inline_scan, registry, repository, tag,
            args, access_token=args.inline_scanner_access_token, account_name=account_name
        ))

    elif args.proxy_scanner:
        scan_msg += '(Proxy Scanner)'
        logger.info(scan_msg)

        session = requests.Session()
        executor_tasks.append(executor.submit(
            initiate_proxy_scan, session, args.proxy_scanner,
            registry, repository, tag
        ))

    else:
        scan_msg += '(Platform Scanner)'
        logger.info(scan_msg)

        executor_tasks.append(executor.submit(
            initiate_platform_scan, lw_client,
            registry, repository, tag
        ))


def scan_containers(lw_client, container_scan_queue, registry_domains, args):
    logger.info(f'Containers to Scan: {len(container_scan_queue)}')

    i = 0

    executor_tasks = []
    scan_errors = []

    with ThreadPoolExecutor(max_workers=WORKER_THREADS) as executor:
        for container in container_scan_queue:
            i += 1

            registry, repository, tag = parse_container_attributes(container)

            if tag == '':
                error_message = f'Skipping {registry}/{repository} as the tag was empty.'
                logger.info(error_message)
                save_failed_scan(f'{registry}/{repository}', tag, error_message)
                continue

            create_scan_task(executor, executor_tasks, lw_client, registry, repository, tag,
                             registry_domains, args, i)

        j = 0
        for task in as_completed(executor_tasks):
            result = task.result()
            if result:
                j += 1
                logger.info(f'Finished scanning {result["repository"]}:{result["tag"]}. ({j} of {i})')
                if result['error'] is not None:
                    scan_errors.append(result)

    if scan_errors:
        logger.info("""\nImages erroring out on scan listed below.  Common issues include the following:
        - The container base image OS is unsupported.
        - The container isn't accessible through currently configured credentials.
        For a list of supported base images, see: https://docs.lacework.com/container-image-support\n""")

        logger.info('Scan Errors:\n' + tabulate(scan_errors, headers='keys'))


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
        logger.setLevel('DEBUG')
        logging.basicConfig(level=logging.DEBUG)

    if args.days:
        days_back = args.days
    else:
        days_back = 1

    subaccounts = [args.subaccount]

    if args.org_level:
        lw_client.set_org_level_access(True)
        user_profile = lw_client.user_profile.get()
        user_profile_data = user_profile.get('data', {})[0]
        lw_client.set_org_level_access(False)

        if user_profile_data.get('orgAccount', False):
            subaccounts = []
            for subaccount in user_profile_data.get('accounts', []):
                if subaccount.get('userEnabled', False):
                    logger.debug(f'Subaccount "{subaccount["accountName"]}" added to list...')
                    subaccounts.append(subaccount['accountName'])

    # Build start/end times
    current_time = datetime.now(timezone.utc)
    start_time = current_time - timedelta(hours=args.hours, days=days_back)
    start_time = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time = current_time
    end_time = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    for subaccount in subaccounts:

        logger.info(f'Setting subaccount to "{subaccount}"')
        lw_client.set_subaccount(subaccount)

        # If a registry is specified, use that
        # Otherwise, scan containers from all integrated domains
        if args.registry:
            registry_domains = [x.strip() for x in str(args.registry).split(',')]
        else:
            registry_domains = get_container_registry_domains(lw_client)

        # Inline scanner usage doesn't need to lookup registries
        # However, we should honor them if manually entered
        if args.inline_scanner or args.inline_scanner_access_token:
            if args.registry:
                container_scan_queue = get_active_containers(lw_client, start_time, end_time, registry_domains)
            else:
                container_scan_queue = get_active_containers(lw_client, start_time, end_time)
        else:
            # Query for active containers across registries
            container_scan_queue = get_active_containers(lw_client, start_time, end_time, registry_domains)

        if args.list_only:
            list_containers(container_scan_queue)
        else:
            if not args.rescan:
                container_scan_queue = deduplicate_scans(lw_client, start_time, end_time,
                                                         container_scan_queue, registry_domains)

            # Scan the containers
            scan_containers(lw_client, container_scan_queue, registry_domains, args)


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
        help="""Use local Inline Scanner to evaluate images rather than Lacework platform
        (will attempt to scan images regardless of registry integration status)"""
    )
    parser.add_argument(
        '--inline-scanner-path',
        type=str,
        help='Path to the Inline Scanner executable (default: lw-scanner expected on path)'
    )
    parser.add_argument(
        '--inline-scanner-access-token',
        default=None,
        type=str,
        help="""Inline Scanner authentication token (in production environments it is recommended
        to use the --inline-scanner argument paried with the LW_ACCESS_TOKEN environment variable)"""
    )
    parser.add_argument(
        '--inline-scanner-only',
        action='store_true',
        help='Use Inline Scanner exculsively (default: use platform scans with inline scanner for unconfigured registries)'
    )
    parser.add_argument(
        '--org-level',
        action='store_true',
        help='Iterate through each Account in an Organization'
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
        logger.error(e)
        parser.print_help()

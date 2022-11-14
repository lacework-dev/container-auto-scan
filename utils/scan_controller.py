# -*- coding: utf-8 -*-

import logging
import json
import os
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from tabulate import tabulate

from utils.scan_runner import ScanRunner

logger = logging.getLogger('auto-scan.scan-controller')


class ScanController:
    """
    A class to manage container scan requests for the Lacework platform.
    """

    SCAN_CACHE_DIR = os.getenv('LW_SCANNER_DATA_DIR', 'cache')
    SCAN_CACHE_FILE = f'{SCAN_CACHE_DIR}/scan_cache.json'
    PAGINATION_MAX = 5000
    SCANNER_INTEGRATION_NAME = 'lacework-auto-scan'
    WORKER_THREADS = int(os.getenv('WORKER_THREADS', 10))

    def __init__(self, lw_client, args, start_time, end_time):
        """
        :param lw_client: An instance of the LaceworkClient from the Lacework Python SDK
        :param args: An argparse arguments object containing optional configuration
            parameters
            :obj
                :param auto_integrate_inline_scanner: A boolean representing whether
                    the ScanController should automatically integrate the Inline Scanner
                    into the current account.
                :param cache_timeout: An integer representing the number of hours in
                    which to cache scan results before retrying.
                :param inline_scanner: A boolean representing whether the ScanController
                    should use the Inline Scanner to execute scans.
                :param inline_scanner_access_token: A string representing the Inline
                    Scanner access token.
                :param inline_scanner_only: A boolean representing whether the
                    ScanController should exclusively use the Inline Scanner to execute
                    scans.
                :param inline_scanner_path: A string representing the path to the
                    Inline Scanner binary. (Defaults to 'lw-scanner')
                :param list_only: A boolean representing whether the ScanController
                    should only list the containers to be scanned.
                :param proxy_scanner: A string representing the Proxy Scanner address
                    that the ScanController should use.
                :param proxy_scanner_skip_validation: A boolean representing whether
                    the ScanController should skip certificate validation for the Proxy
                    Scanner.
                :param registry: A string of comma separated registry domains in which
                    to scan.
                :param rescan: A boolean representing whether the ScanController should
                    ignore the scan cache and rescan all containers.
        :param start_time: A datetime object representing the start time for the active
            container 'lookback' period.
        :param end_time: A datetime object representing the end time for the active
            container 'lookback' period.
        """

        super().__init__()
        self._lw_client = lw_client
        self._start_time = start_time
        self._end_time = end_time

        self._cache_timeout = args.cache_timeout
        self._inline_scanner_access_token = args.inline_scanner_access_token
        self._inline_scanner_only = args.inline_scanner_only
        self._inline_scanner_path = args.inline_scanner_path
        self._proxy_scanner_addr = args.proxy_scanner
        self._proxy_scanner_skip_validation = args.proxy_scanner_skip_validation

        self._scan_all_containers = False

        # Were specified registries specified for the scan
        if args.registry is not None:
            self._registry_specified = True
        else:
            self._registry_specified = False

        # If using the inline/proxy scanner without specified registries, scan
        # all containers
        if (
            args.inline_scanner
            or args.inline_scanner_access_token
            or args.auto_integrate_inline_scanner
            or args.proxy_scanner
        ) and not self._registry_specified:
            self._scan_all_containers = True

        # If registries are specified, use that
        # Otherwise, scan containers from all integrated domains
        if self._registry_specified:
            self._enabled_container_registries = [
                x.strip() for x in str(args.registry).split(',')
            ]
        else:
            self._enabled_container_registries = self._get_container_registry_domains()

        # If using the inline scanner
        if (
            args.inline_scanner
            or args.inline_scanner_access_token
            or args.auto_integrate_inline_scanner
        ):
            self._inline_scanner_access_token = args.inline_scanner_access_token
            # If we're auto integrating the Inline Scanner, get the access token,
            # or create one
            if args.auto_integrate_inline_scanner:
                self._inline_scanner_access_token = (
                    self._get_inline_scanner_access_token()
                )

                if not self._inline_scanner_access_token:
                    self._inline_scanner_access_token = (
                        self._create_inline_scanner_integration()
                    )

        self.scan_cache = None
        self.scan_cache = self._load_scan_cache()
        self.scan_queue = self._get_active_containers()

        if args.list_only:
            self._list_containers()
        else:
            if not args.rescan:
                self._deduplicate_scans()

            # Scan the containers
            self.scan_containers()

    def __del__(self):
        self._save_scan_cache()

    def _build_container_query(self, registry=None):

        query_text = '{ source { LW_HE_CONTAINERS }'

        if registry is not None:
            if registry == 'index.docker.io':
                registry = 'docker.io'
            query_text += f" filter {{ starts_with(REPO, '{registry}') }}"
        else:
            query_text += " filter { REPO <> 'none' }"
        query_text += ' return distinct {REPO, IMAGE_ID, TAG} }'

        logger.debug('Active container LQL query: %s', query_text)

        return query_text

    def _create_inline_scanner_integration(self):
        logger.info('Creating new Inline Scanner...')

        response = self._lw_client.container_registries.create(
            name=self.SCANNER_INTEGRATION_NAME,
            type='ContVulnCfg',
            enabled=True,
            data={'registryType': 'INLINE_SCANNER', 'limitNumScan': '60'},
        )

        logger.info('Inline Scanner created.')
        logger.debug(json.dumps(response))

        access_token = (
            response.get('data', {}).get('serverToken', {}).get('serverToken')
        )

        return access_token

    def _deduplicate_scans(self):

        skipped_containers = 0

        temp_scan_queue = []

        if self._lw_client.subaccount:
            if self._lw_client.subaccount not in self.scan_cache.keys():
                self.scan_cache[self._lw_client.subaccount] = {}
            local_scan_cache = self.scan_cache[self._lw_client.subaccount]
        else:
            local_scan_cache = self.scan_cache

        for container in self.scan_queue:

            registry, repository, image_id, tag = self._parse_container_attributes(
                container
            )

            qualified_repo = f'{registry}/{repository}'

            # Skip if the container has a previous scan within the current window
            if qualified_repo in local_scan_cache.keys():
                if image_id in local_scan_cache[qualified_repo].keys():
                    current_time = int(time.time())
                    try:
                        if (
                            current_time
                            < local_scan_cache[qualified_repo][image_id]['expiry']
                        ):
                            logger.info(
                                'Skipping previously scanned %s with image ID "%s"',
                                qualified_repo,
                                image_id,
                            )
                            skipped_containers += 1
                            continue
                    except KeyError as err:
                        # If this fails, it's likely due to an old cache before
                        # expirations were implemented - Rebuild the cache
                        logger.warning(
                            'KeyError raised on %s. Clearing failed scan cache...', err
                        )
                        os.remove(self.SCAN_CACHE_FILE)

            temp_scan_queue.append(container)

        logger.info('Skipped containers due to previous result: %s', skipped_containers)

        self.scan_queue = temp_scan_queue

    def _get_active_containers(self):
        active_containers = []

        if self._scan_all_containers:
            logger.info('Fetching all active containers...')
            active_containers += self._get_active_container_data()
        else:
            for registry_domain in self._enabled_container_registries:
                logger.info('Fetching active containers for %s...', registry_domain)
                active_containers += self._get_active_container_data(registry_domain)

        return active_containers

    def _get_active_container_data(self, registry_domain=None):
        response = self._lw_client.queries.execute(
            query_text=self._build_container_query(registry_domain),
            arguments={
                'StartTimeRange': self._start_time,
                'EndTimeRange': self._end_time,
            },
        )

        response_containers = response.get('data', [])

        num_returned = len(response_containers)
        if num_returned == self.PAGINATION_MAX:
            logger.warning(
                'Warning! The maximum number of active containers (%s) was returned.',
                self.PAGINATION_MAX,
            )
        logger.info('Found %s active containers...', num_returned)

        return response_containers

    def _get_container_registry_domains(self):
        logger.info('Fetching container registry domains...')

        registries = self._lw_client.container_registries.get()

        registry_domains = []

        for registry in registries['data']:
            registry_domain = registry['data'].get('registryDomain', None)
            if registry['enabled'] and registry_domain:
                if registry_domain not in registry_domains:
                    registry_domains.append(registry_domain)

        logger.info('Returned Container Domains: %s', registry_domains)

        return registry_domains

    def _get_inline_scanner_access_token(self):
        logger.info('Looking for existing Inline Scanner...')

        response = self._lw_client.container_registries.search(
            json={
                'filters': [
                    {
                        'expression': 'eq',
                        'field': 'name',
                        'value': self.SCANNER_INTEGRATION_NAME,
                    }
                ]
            }
        )

        for integration in response.get('data', []):
            logger.info('Inline Scanner found.')
            logger.debug(json.dumps(integration))
            return integration.get('serverToken', {}).get('serverToken')

        logger.info('Inline Scanner not found.')
        return None

    def _list_containers(self):
        for container in self.scan_queue:
            if container['TAG'] == '':
                continue
            logger.info('%s:%s', container['REPO'], container['TAG'])

    def _load_scan_cache(self):
        # To prevent issues reading/writing only load the failed scan cache from disk
        # once. Otherwise, we'll just reference the variable
        if self.scan_cache:
            return self.scan_cache

        # If we have a stored scan cache, then use it
        # Otherwise create an empty one
        if os.path.isfile(self.SCAN_CACHE_FILE):
            # Open the CONFIG_FILE and load it
            with open(self.SCAN_CACHE_FILE, 'r', encoding='utf-8') as scan_cache:
                try:
                    return json.loads(scan_cache.read())
                except Exception as err:
                    # If this fails, it's likely due to an old cache before expirations
                    # were implemented - Rebuild the cache
                    logger.warning(
                        'Error loading failed scan cache: %s. Clearing failed scan '
                        'cache...',
                        err,
                    )
                    os.remove(self.SCAN_CACHE_FILE)
                    return {}
        else:
            return {}

    def _parse_container_attributes(self, container):
        registry, repository = container['REPO'].split('/', 1)
        image_id = container['IMAGE_ID']
        tag = container['TAG']

        if registry == 'docker.io':
            registry = 'index.docker.io'

        return registry, repository, image_id, tag

    def _save_scan_cache(self):
        logger.debug('Writing scan cache to disk...')
        with open(self.SCAN_CACHE_FILE, 'w', encoding='utf-8') as output_file:
            json.dump(self.scan_cache, output_file, indent=2)

    def _update_scan_cache(self, qualified_repo, image_id, status):
        current_time = datetime.now(timezone.utc)
        expiry_time = current_time + timedelta(hours=self._cache_timeout)
        expiry_time = int(expiry_time.timestamp())

        if self._lw_client.subaccount:
            if self._lw_client.subaccount not in self.scan_cache.keys():
                self.scan_cache[self._lw_client.subaccount] = {}
            local_scan_cache = self.scan_cache[self._lw_client.subaccount]
        else:
            local_scan_cache = self.scan_cache

        scan_data = {'status': status, 'expiry': expiry_time}

        if qualified_repo not in local_scan_cache.keys():
            local_scan_cache[qualified_repo] = {image_id: scan_data}
        else:
            local_scan_cache[qualified_repo][image_id] = scan_data

        logger.debug('Updated scan cache: %s', self.scan_cache)

    def scan_containers(self):
        logger.info('Containers to Scan: %s', len(self.scan_queue))

        total_count = 0

        executor_tasks = []
        scan_errors = []

        with ThreadPoolExecutor(max_workers=self.WORKER_THREADS) as executor:
            for container in self.scan_queue:

                registry, repository, image_id, tag = self._parse_container_attributes(
                    container
                )

                if tag == '':
                    error_message = (
                        f'Skipped {registry}/{repository} as the tag was empty.'
                    )
                    logger.info(error_message)
                    self._update_scan_cache(
                        f'{registry}/{repository}', image_id, error_message
                    )
                    continue

                total_count += 1
                self.create_scan_task(
                    executor,
                    executor_tasks,
                    registry,
                    repository,
                    image_id,
                    tag,
                    total_count,
                )

            progress_count = 0
            for task in as_completed(executor_tasks):
                progress_count += 1
                result = task.result()
                if result:
                    logger.info(
                        'Finished scanning %s:%s. (%s of %s)',
                        result['repository'],
                        result['tag'],
                        progress_count,
                        total_count,
                    )
                    if result['status'] != 'Success':
                        scan_errors.append(result)
                    self._update_scan_cache(
                        result['repository'], result['image_id'], result['status']
                    )

        if scan_errors:
            logger.info(
                '\nImages erroring out on scan listed below. Common issues include the '
                'following:'
                '\n- The container base image OS is unsupported.'
                "\n- The container isn\'t accessible through currently configured "
                'credentials.'
                '\nFor a list of supported base images, see: '
                'https://docs.lacework.com/container-image-support\n'
            )

            logger.info('Scan Errors:\n%s', tabulate(scan_errors, headers='keys'))

    def create_scan_task(
        self, executor, executor_tasks, registry, repository, image_id, tag, i
    ):
        scan_msg = f'Scanning {registry}/{repository} with tag "{tag}" ({i}) '
        scan_runner = None

        if self._inline_scanner_access_token and (
            self._inline_scanner_only
            or registry not in self._enabled_container_registries
        ):
            scan_msg += '(Inline Scanner)'
            logger.info(scan_msg)
            scan_runner = ScanRunner(
                self._lw_client,
                'Inline',
                registry,
                repository,
                image_id,
                tag,
                access_token=self._inline_scanner_access_token,
                account_name=self._lw_client._account,
            )
        elif self._proxy_scanner_addr:
            scan_msg += '(Proxy Scanner)'
            logger.info(scan_msg)
            scan_runner = ScanRunner(
                self._lw_client,
                'Proxy',
                registry,
                repository,
                image_id,
                tag,
                proxy_scanner_addr=self._proxy_scanner_addr,
                proxy_scanner_skip_validation=self._proxy_scanner_skip_validation,
            )
        else:
            scan_msg += '(Platform Scanner)'
            logger.info(scan_msg)
            scan_runner = ScanRunner(
                self._lw_client, 'Platform', registry, repository, image_id, tag
            )

        executor_tasks.append(executor.submit(scan_runner.scan))

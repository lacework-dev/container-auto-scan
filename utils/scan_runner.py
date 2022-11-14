# -*- coding: utf-8 -*-

import logging
import os
import subprocess

import docker
import requests

from requests.exceptions import HTTPError

from laceworksdk.exceptions import ApiError, RateLimitError

logger = logging.getLogger('auto-scan.scan-runner')


class ScanRunner:
    """
    A class to execute scan requests for the Lacework platform.
    """

    SCAN_CACHE_DIR = os.getenv('LW_SCANNER_DATA_DIR', 'cache')

    def __init__(
        self,
        lw_client,
        scan_type,
        registry,
        repository,
        image_id,
        tag,
        access_token=None,
        account_name=None,
        inline_scanner_path=None,
        inline_scanner_prune=None,
        proxy_scanner_addr=None,
        proxy_scanner_skip_validation=None,
    ):

        super().__init__()
        self._lw_client = lw_client
        self._image_id = image_id
        self._registry = registry
        self._repository = repository
        self._scan_type = scan_type
        self._tag = tag

        self._access_token = access_token
        self._account_name = account_name
        self._inline_scanner_path = (
            inline_scanner_path if inline_scanner_path else 'lw-scanner'
        )
        self._inline_scanner_prune = inline_scanner_prune

        self._proxy_scanner_addr = proxy_scanner_addr
        self._proxy_scanner_skip_validation = proxy_scanner_skip_validation

        self._qualified_repo = f'{self._registry}/{self._repository}'
        self._status = 'Success'

        self.result = None

    def __del__(self):
        if self._inline_scanner_prune:
            self._prune_image()

    def _build_scan_result(self):
        self.result = {
            'scan_type': self._scan_type,
            'repository': self._qualified_repo,
            'image_id': self._image_id,
            'tag': self._tag,
            'status': self._status,
        }

    def _initiate_inline_scan(self):
        # Build the base command
        command = (
            f'{self._inline_scanner_path} image evaluate '
            f'{self._qualified_repo} {self._tag}'
        )

        # If an inline scanner access token is provided, use it
        # Otherwise we assume that the LW_ACCESS_TOKEN env var is set
        if self._access_token:
            command += f' --access-token {self._access_token}'

        # If an account name is provided, use it
        # Otherwise we assume that the LW_ACCOUNT_NAME env var is set
        if self._account_name:
            command += f' --account-name {self._account_name}'

        # Set the cache directory to local
        command += f' --data-directory {self.SCAN_CACHE_DIR}'

        # Assume we want to save the results to Lacework
        # that's why we're doing this, right?
        command += ' --save'

        logger.debug('Running: %s', command)
        split_command = command.split()
        output = subprocess.run(
            split_command, check=False, capture_output=True, text=True
        )

        if output.stderr:
            error_message = output.stderr.split('\n\n')[-1:][0].rstrip()
            if error_message.lower().startswith('error'):
                self._status = error_message

        logger.debug(output.stdout)

    def _prune_image(self):
        logger.info(
            'Attempting to prune image "%s" from docker...', self._qualified_repo
        )

        try:
            client = docker.from_env()
            client.images.remove(f'{self._qualified_repo}:{self._tag}')
        except HTTPError as error:
            logger.debug(
                'Error pruning image from docker: %s', error
            )

    def _initiate_platform_scan(self):
        try:
            self._lw_client.vulnerabilities.containers.scan(
                self._registry, self._repository, self._tag
            )
        except RateLimitError as error:
            self._status = f'Received rate limit response from Lacework. Error: {error}'
            logger.warning(self._status)
        except ApiError as error:
            self._status = (
                f'Failed to scan container {self._qualified_repo} with tag '
                f'"{self._tag}". Error: {error}'
            )
            logger.warning(self._status)

    def _initiate_proxy_scan(self):
        verify_cert = not bool(self._proxy_scanner_skip_validation)

        try:
            session = requests.Session()
            json = {
                'registry': self._registry,
                'image_name': self._repository,
                'tag': self._tag,
            }

            response = session.post(
                f'{self._proxy_scanner_addr}/v1/scan', json=json, verify=verify_cert
            )
            response.raise_for_status()
        except Exception as error:
            self._status = (
                f'Failed to scan container {self._qualified_repo} with tag '
                f'"{self._tag}". Error: {error}'
            )
            logger.warning(self._status)

    def scan(self):
        if self._scan_type == 'Inline':
            self._initiate_inline_scan()
        elif self._scan_type == 'Platform':
            self._initiate_platform_scan()
        elif self._scan_type == 'Proxy':
            self._initiate_proxy_scan()
        else:
            logger.error('Unsupported scan_type specified. [%s]', self._scan_type)

        self._build_scan_result()
        return self.result

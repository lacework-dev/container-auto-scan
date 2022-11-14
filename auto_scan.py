#!/usr/bin/env python

import argparse
import logging
import os
import time

from datetime import datetime, timedelta, timezone

from laceworksdk import LaceworkClient

from utils.scan_controller import ScanController

INTERVAL = 1200

logging.basicConfig(format='%(asctime)s %(name)s [%(levelname)s] %(message)s')
logger = logging.getLogger('auto-scan')
logger.setLevel(os.getenv('LOG_LEVEL', logging.INFO))


def assess_arguments(args):
    if (
        args.org_level
        and not args.auto_integrate_inline_scanner
        and (args.inline_scanner or args.inline_scanner_access_token)
    ):
        logger.error(
            'Currently the --org-level argument is only compatible with '
            'auto-integrated Inline Scanner.'
        )
        exit()

    # If we're using an inline scanner flag, and have specified registries,
    # but have not specified inline-scanner-only
    if (
        (
            args.inline_scanner
            or args.inline_scanner_access_token
            or args.auto_integrate_inline_scanner
        )
        and args.registry
        and not args.inline_scanner_only
    ):
        logger.warning(
            'Inline scanner in use with --registry specified. '
            'Images from registries will be scanned using platform scanner. '
            'Use --inline-scanner-only to scan images from these target registries '
            'using the inline scanner'
        )

    if args.proxy_scanner and not args.registry:
        logger.warning(
            '--proxy-scanner passed without --registry flag. '
            'Please verify that "scan_public_registries: true" is set in the Proxy '
            'Scanner configuration.'
        )


def main(args):

    assess_arguments(args)

    try:
        lw_client = LaceworkClient(
            account=args.account,
            subaccount=args.subaccount,
            api_key=args.api_key,
            api_secret=args.api_secret,
            profile=args.profile,
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

    subaccounts = [lw_client._subaccount]

    if args.org_level:
        lw_client.set_org_level_access(True)
        user_profile = lw_client.user_profile.get()
        user_profile_data = user_profile.get('data', {})[0]
        lw_client.set_org_level_access(False)

        if user_profile_data.get('orgAccount', False):
            subaccounts = []
            for subaccount in user_profile_data.get('accounts', []):
                if subaccount.get('userEnabled', False):
                    logger.debug(
                        'Subaccount "%s" added to list...', subaccount['accountName']
                    )
                    subaccounts.append(subaccount['accountName'])

    # Build start/end times
    current_time = datetime.now(timezone.utc)
    start_time = current_time - timedelta(hours=args.hours, days=days_back)
    start_time = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time = current_time
    end_time = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    for subaccount in subaccounts:

        logger.info('Setting subaccount to "%s"', subaccount)
        lw_client.set_subaccount(subaccount)

        ScanController(lw_client, args, start_time, end_time)


if __name__ == '__main__':
    # Set up an argument parser
    parser = argparse.ArgumentParser(
        description=(
            'A script to automatically issue container vulnerability scans '
            'to Lacework based on running containers'
        )
    )
    parser.add_argument(
        '--account',
        default=os.environ.get('LW_ACCOUNT', None),
        help='The Lacework account to use',
    )
    parser.add_argument(
        '--subaccount',
        default=os.environ.get('LW_SUBACCOUNT', None),
        help='The Lacework sub-account to use',
    )
    parser.add_argument(
        '--api-key',
        dest='api_key',
        default=os.environ.get('LW_API_KEY', None),
        help='The Lacework API key to use',
    )
    parser.add_argument(
        '--api-secret',
        dest='api_secret',
        default=os.environ.get('LW_API_SECRET', None),
        help='The Lacework API secret to use',
    )
    parser.add_argument(
        '-p',
        '--profile',
        default=os.environ.get('LW_PROFILE', None),
        help='The Lacework CLI profile to use',
    )
    parser.add_argument(
        '--proxy-scanner',
        default=None,
        type=str,
        help='The address of a Lacework proxy scanner: http(s)://[address]:[port]',
    )
    parser.add_argument(
        '--proxy-scanner-skip-validation',
        action='store_true',
        default=False,
        help='Skip validation of Lacework proxy scanner TLS certificate',
    )
    parser.add_argument(
        '--cache-timeout',
        default=24,
        type=int,
        help='The number of hours in which to cache scan results before retrying.'
    )
    parser.add_argument(
        '--days',
        default=os.environ.get('LOOKBACK_DAYS', None),
        type=int,
        help='The number of days in which to search for active containers',
    )
    parser.add_argument(
        '--hours',
        default=0,
        type=int,
        help='The number of hours in which to search for active containers',
    )
    parser.add_argument(
        '--registry',
        help=(
            'The container registry domain(s) for which to issue scans '
            '(comma separated)'
        ),
    )
    parser.add_argument(
        '--rescan',
        dest='rescan',
        action='store_true',
        help='Issue scan requests for previously scanned containers',
    )
    parser.add_argument(
        '--list-only',
        dest='list_only',
        action='store_true',
        help=(
            'Only list active containers for integrated/specified registries '
            '(no scans)'
        ),
    )
    parser.add_argument(
        '--auto-integrate-inline-scanner',
        action='store_true',
        help='Automatically create and use inline scanner integration(s)',
    )
    parser.add_argument(
        '--inline-scanner',
        default=os.environ.get('USE_INLINE_SCANNER', None),
        action='store_true',
        help=(
            'Use local Inline Scanner to evaluate images rather than Lacework platform '
            '(will attempt to scan images regardless of registry integration status)'
        ),
    )
    parser.add_argument(
        '--inline-scanner-path',
        type=str,
        help=(
            'Path to the Inline Scanner executable '
            '(default: lw-scanner expected on path)'
        ),
    )
    parser.add_argument(
        '--inline-scanner-access-token',
        default=None,
        type=str,
        help=(
            'Inline Scanner authentication token (in production environments it is '
            'recommended to use the --inline-scanner argument paried with the '
            'LW_ACCESS_TOKEN environment variable)'
        ),
    )
    parser.add_argument(
        '--inline-scanner-only',
        action='store_true',
        help=(
            'Use Inline Scanner exculsively (default: use platform scans with inline '
            'scanner for unconfigured registries)'
        ),
    )
    parser.add_argument(
        '--org-level',
        action='store_true',
        help='Iterate through each Account in an Organization (Platform Scanner Only)',
    )
    parser.add_argument(
        '-d',
        '--daemon',
        action='store_true',
        help='Run the scanner as a daemon (executes every 20 minutes)',
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        default=os.environ.get('LW_DEBUG', False),
        help='Enable debug logging',
    )
    arguments = parser.parse_args()

    try:
        # If a daemon, create an infinite loop
        if arguments.daemon:
            while True:
                main(arguments)
                time.sleep(INTERVAL)
        else:
            main(arguments)
    except Exception as e:
        logger.error(e, exc_info=True)
        parser.print_help()

import argparse

import pytest

from auto_scan import main
from laceworksdk import LaceworkClient

lw_client = LaceworkClient()


def test_main_default():
    args = argparse.Namespace(
        account=None,
        subaccount=None,
        api_key=None,
        api_secret=None,
        cache_timeout=24,
        auto_integrate_inline_scanner=None,
        inline_scanner=None,
        inline_scanner_path=None,
        inline_scanner_access_token=None,
        inline_scanner_only=None,
        inline_scanner_prune=None,
        org_level=None,
        profile=None,
        proxy_scanner=None,
        proxy_scanner_skip_validation=None,
        days=None,
        hours=0,
        registry=None,
        rescan=None,
        list_only=None,
        daemon=None,
        debug=None,
    )
    main(args)


def test_main_config_fail():
    args = argparse.Namespace(
        account='testing',
        subaccount=None,
        api_key=None,
        api_secret=None,
        auto_integrate_inline_scanner=None,
        cache_timeout=24,
        inline_scanner=None,
        inline_scanner_path=None,
        inline_scanner_access_token=None,
        inline_scanner_only=None,
        inline_scanner_prune=None,
        org_level=None,
        profile=None,
        proxy_scanner=None,
        proxy_scanner_skip_validation=None,
        days=None,
        hours=0,
        registry=None,
        rescan=None,
        list_only=None,
        daemon=None,
        debug=None,
    )
    with pytest.raises(Exception):
        main(args)

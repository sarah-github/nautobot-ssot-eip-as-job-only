"""Job for runnning solidserver to nautobot data sync
"""
# from pprint import pformat

import diffsync  # type: ignore  # pylint: disable=unused-import  # noqa: F401
import netaddr  # type: ignore
from billiard.exceptions import SoftTimeLimitExceeded
from diffsync.enum import DiffSyncFlags
from diffsync.exceptions import ObjectNotCreated
from django.conf import settings  # type: ignore
from django.core.exceptions import ObjectDoesNotExist, ValidationError  # type: ignore
from django.urls import reverse  # type: ignore
from nautobot.core.celery import register_jobs
from nautobot.extras.jobs import (  # type: ignore
    BooleanVar,
    IntegerVar,
    IPNetworkVar,
    Job,
    StringVar,
)
from nautobot.ipam.models import IPAddress, Prefix  # type: ignore
from nautobot_ssot.jobs.base import DataMapping, DataSource  # type: ignore
from nautobot_ssot.models import Sync  # type: ignore
from netaddr import AddrFormatError  # type: ignore

from ssot_solidserver import SSoTEIPSolidServerConfig
from ssot_solidserver.diffsync.adapters import nautobot, solidserver
from ssot_solidserver.utils import ssutils
from ssot_solidserver.utils.ssapi import SolidServerAPI

# PLUGINS_CONFIG = settings.PLUGINS_CONFIG["nautobot_plugin_ssot_eip_solidserver"]
name = "SSoT EIP Solidserver"  # pylint: disable=invalid-name


class SolidserverDataSource(DataSource, Job):
    """Solidserver SSoT Data Source."""

    name_filter_from_ui = StringVar(
        required=False,
        default="",
        label="Optional domain name filter (potentially unreliable!)",
        description="Comma separated list of domains, only used for addresses",
    )
    address_filter_from_ui = IPNetworkVar(
        required=False,
        label="Optional network filter",
        description="Limit sync to a CIDR",
    )
    fetch_addresses = BooleanVar(
        required=False, default=True, label="Compare and sync addresses"
    )
    fetch_prefixes = BooleanVar(
        required=False, default=True, label="Compare and sync prefixes"
    )
    solidserver_timeout = IntegerVar(
        required=False, default=120, label="Timeout (sec) for Solidserver"
    )

    class Meta:
        """Metadata about job"""

        name = "Update Nautobot from EIP SolidSERVER"
        data_source = "Solidserver"
        description = "Sync information from Solidserver to Nautobot"
        commit_default = True
        has_sensitive_variables = False

    def __init__(self) -> None:
        super().__init__()
        self.domain_filter: list[str] = []
        self.client: SolidServerAPI
        self.sync: Sync
        self.diffsync_flags = (
            DiffSyncFlags.CONTINUE_ON_FAILURE
            | DiffSyncFlags.LOG_UNCHANGED_RECORDS
            | DiffSyncFlags.SKIP_UNMATCHED_DST
        )

    @classmethod
    def data_mappings(cls) -> tuple[DataMapping, ...]:
        """List describing the data mappings involved in this DataSource."""
        return (
            DataMapping(
                "IP Addresses", None, "IP Addresses", reverse("ipam:ipaddress_list")
            ),
            DataMapping(
                "IP Prefixes", None, "IP Prefixes", reverse("ipam:prefix_list")
            ),
        )

    @classmethod
    def config_information(cls) -> dict[str, str]:
        """Dictionary describing the configuration of this DataSource."""
        return {
            # "SolidSERVER host": PLUGINS_CONFIG.get("nnn_url", "NOT SET!"),
            # "SolidSERVER user": PLUGINS_CONFIG.get("nnn_user", "NOT SET!"),
            "Plugin version": SSoTEIPSolidServerConfig.version,
            "Plugin build": SSoTEIPSolidServerConfig.build,
        }

    def lookup_object(
        self, model_name: str, unique_id: str
    ) -> IPAddress | Prefix | None:
        """Look up a Nautobot object based on the DiffSync model name and
        unique ID."""
        obj = None
        try:
            if model_name == "ipaddress":
                obj = IPAddress.objects.get(host=unique_id)
            elif model_name == "prefix":
                prefix, prefixlen = unique_id.split("__")
                obj = Prefix.objects.get(network=prefix, prefix_length=prefixlen)
        except ObjectDoesNotExist:
            pass
        return obj

    def load_source_adapter(
        self, get_addrs: bool = True, get_prefixes: bool = True
    ) -> None:
        """Method to instantiate and load the SOURCE adapter into
        `self.source_adapter`."""
        self.log_debug(message="Creating Solidserver adapter")
        self.source_adapter = solidserver.SolidserverAdapter(
            job=self, conn=self.client, sync=self.sync
        )
        self.log_debug(message="Running Solidserver .load()")
        self.source_adapter.load(
            addrs=get_addrs,
            prefixes=get_prefixes,
            address_filter=self.kwargs.get("address_filter_from_ui"),
            domain_filter=self.domain_filter,
        )

    def load_target_adapter(
        self, get_addrs: bool = True, get_prefixes: bool = True
    ) -> None:
        """Method to instantiate and load the TARGET adapter into
        `self.target_adapter`."""
        self.log_debug(message="Creating Nautobot adapter")
        self.target_adapter = nautobot.SSoTNautobotAdapter(job=self, sync=self.sync)
        self.log_debug(message="Starting to run nautobot .load()")
        self.target_adapter.load(
            addrs=get_addrs,
            prefixes=get_prefixes,
            address_filter=self.kwargs.get("address_filter_from_ui"),
            domain_filter=self.domain_filter,
        )

    def sync_data(self) -> None:
        """SSoT plugin required sync_data method
        Loads both adapters, gets data sets from both, runs diff
        operation and, if not dry run, sync operation
        """
        try:
            self.log_debug(f"version {SSoTEIPSolidServerConfig.version}")
            self.log_debug(f"commit {self.kwargs.get('dry_run')}")
        except AttributeError:
            self.log_debug("attr error trying to get self.kwargs[dry_run]")
        if self.kwargs.get("address_filter_from_ui"):
            try:
                netaddr.IPNetwork(self.kwargs.get("address_filter_from_ui", ""))
            except (AddrFormatError, KeyError, AttributeError) as addr_err:
                self.log_failure(message="Address filter is not a CIDR")
                raise ValueError("Address filter is not a CIDR") from addr_err
        if self.kwargs.get("name_filter_from_ui"):
            self.domain_filter, errors = ssutils.domain_name_prep(
                self.kwargs.get("name_filter_from_ui", "")
            )
            if errors:
                for each_err in errors:
                    self.log_failure(message=each_err)
                raise ValueError("Domain filter contains invalid domains")
            message = f"Domain filter list: {self.domain_filter}"
            self.log_debug(message=message)
        self.log_debug(f"Fetch addresses {self.kwargs.get('fetch_addresses')}")
        self.log_debug(f"Fetch prefixes {self.kwargs.get('fetch_prefixes')}")
        self.log_debug(f"CIDR filter {self.kwargs.get('address_filter_from_ui')}")
        self.log_debug(f"Name filter {self.domain_filter}")
        self.log_debug(message="Creating Solidserver connection")
        self.client = SolidServerAPI(
            job=self,
            # username=PLUGINS_CONFIG.get("nnn_user", "username not set"),
            # password=PLUGINS_CONFIG.get("nnn_credential", "password not found"),
            # base_url=PLUGINS_CONFIG.get("nnn_url", "url not set"),
            timeout=self.kwargs.get("solidserver_timeout", 120),
        )

        self.log_info(message="Collecting data from EIP SOLIDServer")
        self.load_source_adapter(
            self.kwargs.get("fetch_addresses", True),
            self.kwargs.get("fetch_prefixes", True),
        )
        try:
            self.log_debug(
                f"Got {len(self.source_adapter.dict().get('prefix', []))} "
                + "prefixes from SS"
            )
            self.log_debug(
                f"Got {len(self.source_adapter.dict().get('ipaddress', []))} "
                + "addresses from SS"
            )
            self.log_debug(f"Keys: {self.source_adapter.dict().keys()}")
            self.log_debug(f"Prefixes: {self.source_adapter.dict().get('prefix', '')}")
            self.log_debug(
                f"Addresses: {self.source_adapter.dict().get('ipaddress', '')}"
            )
        except AttributeError:
            self.log_debug(message="Couldn't get length from source adapter")
        self.log_info(message="Collecting data from Nautobot")
        self.load_target_adapter(
            self.kwargs.get("fetch_addresses", True),
            self.kwargs.get("fetch_prefixes", True),
        )
        try:
            self.log_debug(
                f"Got {len(self.target_adapter.dict().get('prefix', []))} "
                + "prefixes from NB"
            )
            self.log_debug(
                f"Got {len(self.target_adapter.dict().get('ipaddress', []))} "
                + "addresses from NB"
            )
            self.log_debug(f"Keys: {self.target_adapter.dict().keys()}")
            self.log_debug(f"Prefixes: {self.target_adapter.dict().get('prefix', '')}")
            self.log_debug(
                f"Addresses: {self.target_adapter.dict().get('ipaddress', '')}"
            )
        except AttributeError:
            self.log_debug(message="Couldn't get length from target adapter")

        self.log_info("Calculating diffs...")
        diff = self.source_adapter.diff_to(self.target_adapter)
        self.log_info(f"Found {len(diff)} differences pre-filtering")
        self.log_info(f"{diff.summary()}")
        # self.log_debug(pformat(diff.dict()))

        # filtering the source adapter to get rid of any diffs that are solely
        # status__name changes, and updating any diffs where status__name
        # exists in the target_adapter to match the target_adapter
        self.source_adapter = ssutils.filter_diff_for_status(
            diff, self.source_adapter, self.target_adapter
        )
        diff = self.source_adapter.diff_to(self.target_adapter)
        self.log_info(f"Found {len(diff)} differences post-filtering")
        self.log_info(f"{diff.summary()}")

        if not self.kwargs.get("dry_run"):
            try:
                self.source_adapter.sync_to(self.target_adapter)
                self.log_success(message="Sync succeeded.")
            except ValidationError as valid_err:
                self.log_failure(
                    f"Validation error {valid_err}.  If this is a name query it may be"
                    " that some addresses in Nautobot are missing FQDNs so they can't"
                    " be matched to Solidserver and this job has tried to create"
                    " duplicate addresses."
                )
            except ObjectNotCreated as create_err:
                self.log_failure(f"Unable to create object {create_err}")
            except SoftTimeLimitExceeded as timeout_err:
                self.log_failure(
                    f"Query exceeded timeout! {timeout_err}"
                    " Consider re-running the job with a larger timeout"
                    " or a smaller address filter."
                )


jobs = [SolidserverDataSource]
register_jobs(SolidserverDataSource)

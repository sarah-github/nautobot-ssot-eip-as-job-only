"""Adapter to collect IP addresses and prefixes from Solidserver
and creates DiffSync models
"""
from typing import Any

from diffsync import DiffSync
from diffsync.exceptions import ObjectAlreadyExists
from nautobot.extras.jobs import Job  # type: ignore
from nautobot_ssot.models import Sync  # type: ignore

from ...constants import IPV4_SUBNET_SIZE_MAP
from ..models.solidserver import (
    SolidserverIPAddress,
    SolidserverIPPrefix,
)
from ...utils import ssapi, ssutils


class SolidserverAdapter(DiffSync):
    """DiffSync adapter for Solidserver"""

    ipaddress = SolidserverIPAddress
    prefix = SolidserverIPPrefix

    top_level = ["ipaddress", "prefix"]

    def __init__(
        self, *args, job: Job, conn: ssapi.SolidServerAPI, sync: Sync, **kwargs
    ) -> None:
        """Initialize the Solidserver DiffSync adapter."""
        super().__init__(*args, **kwargs)
        self.job: Job = job
        self.conn: ssapi.SolidServerAPI = conn
        self.sync: Sync = sync

    def _add_object_to_diffsync(self, obj: Any) -> None:
        try:
            self.add(obj)
            self.job.log_debug(f"SS Adapter added {obj}")
        except ObjectAlreadyExists as err:
            if isinstance(obj, SolidserverIPAddress):
                self.job.log_warning(f"SS Adapter skipping duplicate {obj.host}. {err}")
            elif isinstance(obj, SolidserverIPPrefix):
                self.job.log_warning(
                    f"SS Adapter skipping duplicate {obj.network} "
                    + f"/{obj.prefix_length}. {err}"
                )

    def _process_ipv4_addr(self, each_addr: dict[str, str]) -> int | None:
        """Convert one Solidserver IP4 record into a diffsync model

        Args:
            each_addr (dict): the Solidserver address record

        Returns:
            int | None: the subnet_id of the address record
        """
        try:
            cidr_size: int = IPV4_SUBNET_SIZE_MAP.get(
                int(each_addr.get("subnet_size", 1)), 32
            )
        except (ValueError, KeyError):
            cidr_size = 32
        try:
            descr = ssutils.unpack_class_params(each_addr["ip_class_parameters"]).get(
                "__eip_description"
            )
            if not descr:
                descr = " "
        except (ValueError, KeyError):
            descr = " "
        except AttributeError:
            message = f"ip_class params: {each_addr['ip_class_parameters']}"
            self.job.log_debug(message=message)
            descr = ""
        new_addr = self.ipaddress(
            dns_name=each_addr.get("name"),
            description=descr,
            host=str(each_addr.get("hostaddr")),
            solidserver_addr_id=each_addr.get("ip_id", "not found"),
            prefix_length=cidr_size,
        )
        if new_addr:
            valid_addr, new_addr_or_err = ssutils.is_addr_valid(
                new_addr, each_addr.get("type", "free")
            )
            if valid_addr:
                self._add_object_to_diffsync(new_addr_or_err)
            else:
                self.job.log_warning(new_addr_or_err)
        if new_addr and new_addr.prefix_length:
            return int(each_addr.get("subnet_id", 0)) or None
        return None

    def _process_ipv6_addr(self, each_addr: dict[str, str]) -> int | None:
        """Convert one Solidserver IP6 record into a diffsync model

        Args:
            each_addr (dict): the Solidserver address record

        Returns:
            int | None: the subnet_id of the address record
        """
        try:
            cidr_size: int = int(each_addr.get("subnet6_prefix", 128))
        except (ValueError, KeyError):
            cidr_size = 128
        try:
            descr = ssutils.unpack_class_params(each_addr["ip6_class_parameters"]).get(
                "__eip_description"
            )
            if not descr:
                descr = " "
        except (ValueError, KeyError):
            descr = " "
        except AttributeError:
            self.job.log_debug(f"ip_class params: {each_addr['ip6_class_parameters']}")
            descr = ""
        new_addr = self.ipaddress(
            dns_name=each_addr.get("ip6_name", ""),
            description=descr,
            host=str(each_addr.get("hostaddr")),
            solidserver_addr_id=each_addr.get("ip6_id", "not found"),
            prefix_length=cidr_size,
        )
        if new_addr:
            valid_addr, new_addr_or_err = ssutils.is_addr_valid(
                new_addr, each_addr.get("type", "free")
            )
            if valid_addr:
                self._add_object_to_diffsync(new_addr_or_err)
            else:
                self.job.log_warning(new_addr_or_err)
        if new_addr and new_addr.prefix_length:
            return int(each_addr.get("subnet6_id", 0)) or None
        return None

    def _process_ipv4_prefix(self, each_prefix: dict[str, str]) -> None:
        """Convert one Solidserver IP4 record into a diffsync model

        Args:
            each_prefix (dict): the Solidserver prefix record
        """
        try:
            cidr_size: int = IPV4_SUBNET_SIZE_MAP.get(
                int(each_prefix.get("subnet_size", 1)), 32
            )
        except (ValueError, KeyError):
            cidr_size = 32
        try:
            descr = ssutils.unpack_class_params(each_prefix["ip_class_parameters"]).get(
                "__eip_description"
            )
            if not descr:
                descr = " "
        except (ValueError, KeyError):
            descr = " "
        self.job.log_debug(
            f"About to create prefix {each_prefix.get('start_hostaddr')}/{cidr_size}"
        )
        new_prefix = self.prefix(
            description=descr,
            network=str(each_prefix.get("start_hostaddr")),
            solidserver_addr_id=each_prefix.get("subnet_id", "not found"),
            prefix_length=cidr_size,
        )
        if new_prefix:
            self.job.log_debug(
                f"new prefix {new_prefix.network}/{new_prefix.prefix_length}"
            )
            valid_prefix, error = ssutils.is_prefix_valid(new_prefix)
            if not valid_prefix:
                self.job.log_warning(
                    "Invalid prefix"
                    f" {new_prefix.network}/{new_prefix.prefix_length}, err: {error}"
                )
                return
            self._add_object_to_diffsync(new_prefix)

    def _process_ipv6_prefix(self, each_prefix: dict[str, str]) -> None:
        """Convert one Solidserver IP6 record into a diffsync model

        Args:
            each_prefix (dict): the Solidserver prefix record
        """
        try:
            descr = ssutils.unpack_class_params(
                each_prefix["ip6_class_parameters"]
            ).get("__eip_description")
            if not descr:
                descr = " "
        except (ValueError, KeyError):
            descr = " "
        self.job.log_debug(
            f"About to create prefix {each_prefix.get('subnet6_name')}/"
            + f"{each_prefix.get('subnet6_prefix')}"
        )
        new_prefix = self.prefix(
            description=descr,
            network=str(each_prefix.get("start_hostaddr")),
            solidserver_addr_id=each_prefix.get("subnet6_id", "not found"),
            prefix_length=int(each_prefix.get("subnet6_prefix", 128)),
        )
        if new_prefix:
            valid_prefix, error = ssutils.is_prefix_valid(new_prefix)
            if not valid_prefix:
                self.job.log_warning(
                    "Invalid prefix"
                    f" {new_prefix.network}/{new_prefix.prefix_length}, err: {error}"
                )
                return
            self._add_object_to_diffsync(new_prefix)

    def _load_addresses(self, address_filter=None, domain_filter=None):
        """Run the api queries against Solidserver, using filters if given,
        then convert results into diffsync models

        Args:
            address_filter (str or list, optional): CIDR filter. Defaults to
            None.
            domain_filter (str or list, optional): Domain name filter. Defaults
            to None.

        Returns:
            list: a list of unique prefix IDs collected from parent network
            attribute of addresses
        """
        all_addrs = []
        prefix_ids = []
        if address_filter:
            message = f"Starting to filter addresses with {address_filter}"
            self.job.log_debug(message=message)
            filter_addrs = self.conn.get_addresses_by_network(address_filter)
            message = f"Got {len(filter_addrs)} back"
            self.job.log_debug(message=message)
            if filter_addrs:
                message = f"address filter {len(filter_addrs)} addrs"
                self.job.log_debug(message=message)
                all_addrs.extend(filter_addrs)
        if domain_filter:
            message = f"Starting to filter addresses with {domain_filter}"
            self.job.log_debug(message=message)
            filter_names = self.conn.get_addresses_by_name(domain_filter)
            message = f"Got {len(filter_names)} back"
            self.job.log_debug(message=message)
            if filter_names:
                message = f"name filter {len(filter_names)} addrs"
                self.job.log_debug(message=message)
                all_addrs.extend(filter_names)
        if not address_filter and not domain_filter:
            message = "Starting to gather unfiltered addresses"
            self.job.log_debug(message=message)
            all_addrs = self.conn.get_all_addresses()
            message = f"no filter {len(all_addrs)}"
            self.job.log_debug(message=message)

        for each_addr in all_addrs:
            if each_addr.get("hostaddr"):
                subnet_id = None
                if each_addr.get("ip_id"):
                    # ipv4
                    subnet_id = self._process_ipv4_addr(each_addr)
                elif each_addr.get("ip6_id"):
                    # ipv6
                    subnet_id = self._process_ipv6_addr(each_addr)
                if subnet_id and subnet_id not in prefix_ids:
                    prefix_ids.append(subnet_id)
        return prefix_ids

    def _load_prefixes(self, address_filter=None, subnet_list=None):
        """Run the api queries against Solidserver, using filters if given,
        then convert results into diffsync models

        Args:
            address_filter (str or list, optional): CIDR filter. Defaults to
            None.
            subnet_list (list, optional): If addresses have been loaded,
            this will be a list of the parent network IDs for all of the
            addresses
        """
        all_prefixes = []
        if address_filter:
            self.job.log_debug(
                message=f"About to query for address filter {address_filter}"
            )
            filter_prefixes = self.conn.get_prefixes_by_network(address_filter)
            if filter_prefixes:
                all_prefixes.extend(filter_prefixes)
                self.job.log_debug(
                    message=f"Address filter prefixes has {len(filter_prefixes)} items"
                )
        if subnet_list:
            self.job.log_debug(message=f"Subnet list has {len(subnet_list)} items")
            filter_name_prefixes = self.conn.get_prefixes_by_id(
                subnet_list=subnet_list, address_filter=address_filter
            )
            self.job.log_debug(
                message=(
                    f"Filter name prefixes has {len(filter_name_prefixes)} items with"
                )
                + f" filters {address_filter} and subnet_list {subnet_list}"
            )
            self.job.log_debug(message=f"Subnet list has {len(subnet_list)} items")
            if filter_name_prefixes:
                self.job.log_debug(message="Adding filter name prefixes")
                all_prefixes.extend(filter_name_prefixes)
        if not address_filter and not subnet_list:
            all_prefixes = self.conn.get_all_prefixes()
            message = f"No filter total {len(all_prefixes)} prefixes"
            self.job.log_debug(message=message)

        self.job.log_debug(f"Processing {len(all_prefixes)} prefixes")
        for each_prefix in all_prefixes:
            if isinstance(each_prefix, list):
                if len(each_prefix) != 1:
                    self.job.log_warning(message=f"Too many prefixes! {each_prefix}")
                    continue
                each_prefix = each_prefix[0]
            self.job.log_debug(f"Processing {each_prefix.get('subnet_name')}")
            if each_prefix.get("is_terminal"):
                if each_prefix.get("subnet_id"):
                    # ipv4
                    try:
                        cidr_size: int = IPV4_SUBNET_SIZE_MAP.get(
                            int(each_prefix.get("subnet_size", 1)), 32
                        )
                    except (ValueError, KeyError):
                        cidr_size = 32
                    self.job.log_debug(
                        message=f"Range {each_prefix.get('start_hostaddr')}/{cidr_size}"
                    )
                    self._process_ipv4_prefix(each_prefix)
                elif each_prefix.get("subnet6_id"):
                    # ipv6
                    self.job.log_debug(
                        message=(
                            "Range"
                            f" {each_prefix.get('start_hostaddr')}/{each_prefix.get('subnet_size')}"
                        )
                    )
                    self._process_ipv6_prefix(each_prefix)

    def load(self, addrs=True, prefixes=True, address_filter=None, domain_filter=None):
        """Load data sets and return the populated DiffSync adapter
        objects."""
        prefix_ids = None
        if addrs:
            self.job.log_debug("Starting to load addresses")
            prefix_ids = self._load_addresses(address_filter, domain_filter)
        if prefixes:
            self.job.log_debug("Starting to load prefixes")
            self._load_prefixes(address_filter, prefix_ids)

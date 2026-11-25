from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DriverState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DRIVER_ABSENT: _ClassVar[DriverState]
    DRIVER_SERVICE: _ClassVar[DriverState]
    DRIVER_MANUAL_MAPPED: _ClassVar[DriverState]

class InputButton(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INPUT_LEFT: _ClassVar[InputButton]
    INPUT_RIGHT: _ClassVar[InputButton]
    INPUT_MIDDLE: _ClassVar[InputButton]
    INPUT_X1: _ClassVar[InputButton]
    INPUT_X2: _ClassVar[InputButton]

class InputAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INPUT_DOWN: _ClassVar[InputAction]
    INPUT_UP: _ClassVar[InputAction]
    INPUT_CLICK: _ClassVar[InputAction]

class MemSpace(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    USER: _ClassVar[MemSpace]
    KERNEL: _ClassVar[MemSpace]
    PHYSICAL: _ClassVar[MemSpace]

class ShellKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CMD: _ClassVar[ShellKind]
    POWERSHELL: _ClassVar[ShellKind]

class CallSpace(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CALL_USER: _ClassVar[CallSpace]
    CALL_KERNEL: _ClassVar[CallSpace]

class EventsKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EVENTS_KIND_UNSPECIFIED: _ClassVar[EventsKind]
    EVENTS_PROC_CREATE: _ClassVar[EventsKind]
    EVENTS_PROC_EXIT: _ClassVar[EventsKind]
    EVENTS_IMAGE_LOAD: _ClassVar[EventsKind]
    EVENTS_THREAD_CREATE: _ClassVar[EventsKind]
    EVENTS_THREAD_EXIT: _ClassVar[EventsKind]
    EVENTS_KIND_BP_HIT: _ClassVar[EventsKind]

class ScanDiskSpillMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SCAN_SPILL_AUTO: _ClassVar[ScanDiskSpillMode]
    SCAN_SPILL_RAM_ONLY: _ClassVar[ScanDiskSpillMode]
DRIVER_ABSENT: DriverState
DRIVER_SERVICE: DriverState
DRIVER_MANUAL_MAPPED: DriverState
INPUT_LEFT: InputButton
INPUT_RIGHT: InputButton
INPUT_MIDDLE: InputButton
INPUT_X1: InputButton
INPUT_X2: InputButton
INPUT_DOWN: InputAction
INPUT_UP: InputAction
INPUT_CLICK: InputAction
USER: MemSpace
KERNEL: MemSpace
PHYSICAL: MemSpace
CMD: ShellKind
POWERSHELL: ShellKind
CALL_USER: CallSpace
CALL_KERNEL: CallSpace
EVENTS_KIND_UNSPECIFIED: EventsKind
EVENTS_PROC_CREATE: EventsKind
EVENTS_PROC_EXIT: EventsKind
EVENTS_IMAGE_LOAD: EventsKind
EVENTS_THREAD_CREATE: EventsKind
EVENTS_THREAD_EXIT: EventsKind
EVENTS_KIND_BP_HIT: EventsKind
SCAN_SPILL_AUTO: ScanDiskSpillMode
SCAN_SPILL_RAM_ONLY: ScanDiskSpillMode

class OpStatus(_message.Message):
    __slots__ = ("ok", "error", "errno_code", "kind")
    OK_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    ERRNO_CODE_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ok: bool
    error: str
    errno_code: int
    kind: str
    def __init__(self, ok: _Optional[bool] = ..., error: _Optional[str] = ..., errno_code: _Optional[int] = ..., kind: _Optional[str] = ...) -> None: ...

class StatusRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class StatusResponse(_message.Message):
    __slots__ = ("status", "agent_version", "os_version", "os_build", "testsigning", "hvci", "secureboot", "driver_state", "driver_version", "patchguard_expected", "agent_uptime_ms", "boot_epoch_ms", "agent_instance_id", "ipv4", "scan_service_version", "pointer_map_version", "dissect_version", "memory_heap_attrib_version", "driver_abi_version", "agent_abi_version", "driver_abi_ok")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    AGENT_VERSION_FIELD_NUMBER: _ClassVar[int]
    OS_VERSION_FIELD_NUMBER: _ClassVar[int]
    OS_BUILD_FIELD_NUMBER: _ClassVar[int]
    TESTSIGNING_FIELD_NUMBER: _ClassVar[int]
    HVCI_FIELD_NUMBER: _ClassVar[int]
    SECUREBOOT_FIELD_NUMBER: _ClassVar[int]
    DRIVER_STATE_FIELD_NUMBER: _ClassVar[int]
    DRIVER_VERSION_FIELD_NUMBER: _ClassVar[int]
    PATCHGUARD_EXPECTED_FIELD_NUMBER: _ClassVar[int]
    AGENT_UPTIME_MS_FIELD_NUMBER: _ClassVar[int]
    BOOT_EPOCH_MS_FIELD_NUMBER: _ClassVar[int]
    AGENT_INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    IPV4_FIELD_NUMBER: _ClassVar[int]
    SCAN_SERVICE_VERSION_FIELD_NUMBER: _ClassVar[int]
    POINTER_MAP_VERSION_FIELD_NUMBER: _ClassVar[int]
    DISSECT_VERSION_FIELD_NUMBER: _ClassVar[int]
    MEMORY_HEAP_ATTRIB_VERSION_FIELD_NUMBER: _ClassVar[int]
    DRIVER_ABI_VERSION_FIELD_NUMBER: _ClassVar[int]
    AGENT_ABI_VERSION_FIELD_NUMBER: _ClassVar[int]
    DRIVER_ABI_OK_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    agent_version: str
    os_version: str
    os_build: int
    testsigning: bool
    hvci: bool
    secureboot: bool
    driver_state: DriverState
    driver_version: str
    patchguard_expected: bool
    agent_uptime_ms: int
    boot_epoch_ms: int
    agent_instance_id: str
    ipv4: _containers.RepeatedCompositeFieldContainer[AdapterInfo]
    scan_service_version: int
    pointer_map_version: int
    dissect_version: int
    memory_heap_attrib_version: int
    driver_abi_version: int
    agent_abi_version: int
    driver_abi_ok: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., agent_version: _Optional[str] = ..., os_version: _Optional[str] = ..., os_build: _Optional[int] = ..., testsigning: _Optional[bool] = ..., hvci: _Optional[bool] = ..., secureboot: _Optional[bool] = ..., driver_state: _Optional[_Union[DriverState, str]] = ..., driver_version: _Optional[str] = ..., patchguard_expected: _Optional[bool] = ..., agent_uptime_ms: _Optional[int] = ..., boot_epoch_ms: _Optional[int] = ..., agent_instance_id: _Optional[str] = ..., ipv4: _Optional[_Iterable[_Union[AdapterInfo, _Mapping]]] = ..., scan_service_version: _Optional[int] = ..., pointer_map_version: _Optional[int] = ..., dissect_version: _Optional[int] = ..., memory_heap_attrib_version: _Optional[int] = ..., driver_abi_version: _Optional[int] = ..., agent_abi_version: _Optional[int] = ..., driver_abi_ok: _Optional[bool] = ...) -> None: ...

class IdentifyRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class IdentifyResponse(_message.Message):
    __slots__ = ("computer_name", "boot_epoch_ms", "agent_instance_id", "agent_version", "view_kind")
    COMPUTER_NAME_FIELD_NUMBER: _ClassVar[int]
    BOOT_EPOCH_MS_FIELD_NUMBER: _ClassVar[int]
    AGENT_INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    AGENT_VERSION_FIELD_NUMBER: _ClassVar[int]
    VIEW_KIND_FIELD_NUMBER: _ClassVar[int]
    computer_name: str
    boot_epoch_ms: int
    agent_instance_id: str
    agent_version: str
    view_kind: str
    def __init__(self, computer_name: _Optional[str] = ..., boot_epoch_ms: _Optional[int] = ..., agent_instance_id: _Optional[str] = ..., agent_version: _Optional[str] = ..., view_kind: _Optional[str] = ...) -> None: ...

class AdapterInfo(_message.Message):
    __slots__ = ("adapter", "address", "prefix_len", "origin", "gateway", "mac", "up")
    ADAPTER_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    PREFIX_LEN_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_FIELD_NUMBER: _ClassVar[int]
    MAC_FIELD_NUMBER: _ClassVar[int]
    UP_FIELD_NUMBER: _ClassVar[int]
    adapter: str
    address: str
    prefix_len: int
    origin: str
    gateway: str
    mac: str
    up: bool
    def __init__(self, adapter: _Optional[str] = ..., address: _Optional[str] = ..., prefix_len: _Optional[int] = ..., origin: _Optional[str] = ..., gateway: _Optional[str] = ..., mac: _Optional[str] = ..., up: _Optional[bool] = ...) -> None: ...

class DriverLoadRequest(_message.Message):
    __slots__ = ("method", "image_path", "mapper_path")
    class Method(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        SERVICE: _ClassVar[DriverLoadRequest.Method]
        MANUAL_MAP: _ClassVar[DriverLoadRequest.Method]
    SERVICE: DriverLoadRequest.Method
    MANUAL_MAP: DriverLoadRequest.Method
    METHOD_FIELD_NUMBER: _ClassVar[int]
    IMAGE_PATH_FIELD_NUMBER: _ClassVar[int]
    MAPPER_PATH_FIELD_NUMBER: _ClassVar[int]
    method: DriverLoadRequest.Method
    image_path: str
    mapper_path: str
    def __init__(self, method: _Optional[_Union[DriverLoadRequest.Method, str]] = ..., image_path: _Optional[str] = ..., mapper_path: _Optional[str] = ...) -> None: ...

class DriverUnloadRequest(_message.Message):
    __slots__ = ("delete_service",)
    DELETE_SERVICE_FIELD_NUMBER: _ClassVar[int]
    delete_service: bool
    def __init__(self, delete_service: _Optional[bool] = ...) -> None: ...

class SelfUpdateRequest(_message.Message):
    __slots__ = ("service_name", "exe_path", "staged_path", "sha256", "listen_port")
    SERVICE_NAME_FIELD_NUMBER: _ClassVar[int]
    EXE_PATH_FIELD_NUMBER: _ClassVar[int]
    STAGED_PATH_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    LISTEN_PORT_FIELD_NUMBER: _ClassVar[int]
    service_name: str
    exe_path: str
    staged_path: str
    sha256: str
    listen_port: str
    def __init__(self, service_name: _Optional[str] = ..., exe_path: _Optional[str] = ..., staged_path: _Optional[str] = ..., sha256: _Optional[str] = ..., listen_port: _Optional[str] = ...) -> None: ...

class RecentOpsRequest(_message.Message):
    __slots__ = ("limit", "include_prior")
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_PRIOR_FIELD_NUMBER: _ClassVar[int]
    limit: int
    include_prior: bool
    def __init__(self, limit: _Optional[int] = ..., include_prior: _Optional[bool] = ...) -> None: ...

class BreadcrumbOp(_message.Message):
    __slots__ = ("t_start_us", "t_end_us", "ioctl_code", "arg_summary", "status_code", "status_kind", "latency_us")
    T_START_US_FIELD_NUMBER: _ClassVar[int]
    T_END_US_FIELD_NUMBER: _ClassVar[int]
    IOCTL_CODE_FIELD_NUMBER: _ClassVar[int]
    ARG_SUMMARY_FIELD_NUMBER: _ClassVar[int]
    STATUS_CODE_FIELD_NUMBER: _ClassVar[int]
    STATUS_KIND_FIELD_NUMBER: _ClassVar[int]
    LATENCY_US_FIELD_NUMBER: _ClassVar[int]
    t_start_us: int
    t_end_us: int
    ioctl_code: int
    arg_summary: str
    status_code: int
    status_kind: str
    latency_us: int
    def __init__(self, t_start_us: _Optional[int] = ..., t_end_us: _Optional[int] = ..., ioctl_code: _Optional[int] = ..., arg_summary: _Optional[str] = ..., status_code: _Optional[int] = ..., status_kind: _Optional[str] = ..., latency_us: _Optional[int] = ...) -> None: ...

class RecentOpsResponse(_message.Message):
    __slots__ = ("status", "current", "prior", "agent_start_epoch_ms", "now_epoch_ms")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CURRENT_FIELD_NUMBER: _ClassVar[int]
    PRIOR_FIELD_NUMBER: _ClassVar[int]
    AGENT_START_EPOCH_MS_FIELD_NUMBER: _ClassVar[int]
    NOW_EPOCH_MS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    current: _containers.RepeatedCompositeFieldContainer[BreadcrumbOp]
    prior: _containers.RepeatedCompositeFieldContainer[BreadcrumbOp]
    agent_start_epoch_ms: int
    now_epoch_ms: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., current: _Optional[_Iterable[_Union[BreadcrumbOp, _Mapping]]] = ..., prior: _Optional[_Iterable[_Union[BreadcrumbOp, _Mapping]]] = ..., agent_start_epoch_ms: _Optional[int] = ..., now_epoch_ms: _Optional[int] = ...) -> None: ...

class HostInfoRequest(_message.Message):
    __slots__ = ("include_security_products", "include_hardware")
    INCLUDE_SECURITY_PRODUCTS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_HARDWARE_FIELD_NUMBER: _ClassVar[int]
    include_security_products: bool
    include_hardware: bool
    def __init__(self, include_security_products: _Optional[bool] = ..., include_hardware: _Optional[bool] = ...) -> None: ...

class SecurityProduct(_message.Message):
    __slots__ = ("name", "state", "version", "kind")
    NAME_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    name: str
    state: str
    version: str
    kind: str
    def __init__(self, name: _Optional[str] = ..., state: _Optional[str] = ..., version: _Optional[str] = ..., kind: _Optional[str] = ...) -> None: ...

class HostInfoResponse(_message.Message):
    __slots__ = ("status", "computer_name", "dns_hostname", "domain", "logged_on_user", "agent_run_as", "is_elevated", "product_name", "edition_id", "display_version", "release_id", "build_major", "build_ubr", "full_build_string", "install_date", "boot_time", "timezone", "arch", "testsigning", "testsigning_source", "hvci", "hvci_source", "secureboot", "secureboot_source", "kernel_debugger", "kernel_debugger_source", "vbs_enabled", "vbs_source", "credential_guard", "credential_guard_source", "driver_blocklist_on", "driver_blocklist_source", "lsa_protected", "lsa_protected_source", "smep", "smap", "cet_shstk", "patchguard_state", "kva_shadow", "kva_shadow_source", "cpu_brand", "cpu_cores", "cpu_logical", "phys_mem_bytes", "hypervisor_vendor", "is_vm", "pc_uptime_ms", "agent_uptime_ms", "service_uptime_ms", "security_products", "probe_errors", "ipv4")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    COMPUTER_NAME_FIELD_NUMBER: _ClassVar[int]
    DNS_HOSTNAME_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    LOGGED_ON_USER_FIELD_NUMBER: _ClassVar[int]
    AGENT_RUN_AS_FIELD_NUMBER: _ClassVar[int]
    IS_ELEVATED_FIELD_NUMBER: _ClassVar[int]
    PRODUCT_NAME_FIELD_NUMBER: _ClassVar[int]
    EDITION_ID_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_VERSION_FIELD_NUMBER: _ClassVar[int]
    RELEASE_ID_FIELD_NUMBER: _ClassVar[int]
    BUILD_MAJOR_FIELD_NUMBER: _ClassVar[int]
    BUILD_UBR_FIELD_NUMBER: _ClassVar[int]
    FULL_BUILD_STRING_FIELD_NUMBER: _ClassVar[int]
    INSTALL_DATE_FIELD_NUMBER: _ClassVar[int]
    BOOT_TIME_FIELD_NUMBER: _ClassVar[int]
    TIMEZONE_FIELD_NUMBER: _ClassVar[int]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    TESTSIGNING_FIELD_NUMBER: _ClassVar[int]
    TESTSIGNING_SOURCE_FIELD_NUMBER: _ClassVar[int]
    HVCI_FIELD_NUMBER: _ClassVar[int]
    HVCI_SOURCE_FIELD_NUMBER: _ClassVar[int]
    SECUREBOOT_FIELD_NUMBER: _ClassVar[int]
    SECUREBOOT_SOURCE_FIELD_NUMBER: _ClassVar[int]
    KERNEL_DEBUGGER_FIELD_NUMBER: _ClassVar[int]
    KERNEL_DEBUGGER_SOURCE_FIELD_NUMBER: _ClassVar[int]
    VBS_ENABLED_FIELD_NUMBER: _ClassVar[int]
    VBS_SOURCE_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_GUARD_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_GUARD_SOURCE_FIELD_NUMBER: _ClassVar[int]
    DRIVER_BLOCKLIST_ON_FIELD_NUMBER: _ClassVar[int]
    DRIVER_BLOCKLIST_SOURCE_FIELD_NUMBER: _ClassVar[int]
    LSA_PROTECTED_FIELD_NUMBER: _ClassVar[int]
    LSA_PROTECTED_SOURCE_FIELD_NUMBER: _ClassVar[int]
    SMEP_FIELD_NUMBER: _ClassVar[int]
    SMAP_FIELD_NUMBER: _ClassVar[int]
    CET_SHSTK_FIELD_NUMBER: _ClassVar[int]
    PATCHGUARD_STATE_FIELD_NUMBER: _ClassVar[int]
    KVA_SHADOW_FIELD_NUMBER: _ClassVar[int]
    KVA_SHADOW_SOURCE_FIELD_NUMBER: _ClassVar[int]
    CPU_BRAND_FIELD_NUMBER: _ClassVar[int]
    CPU_CORES_FIELD_NUMBER: _ClassVar[int]
    CPU_LOGICAL_FIELD_NUMBER: _ClassVar[int]
    PHYS_MEM_BYTES_FIELD_NUMBER: _ClassVar[int]
    HYPERVISOR_VENDOR_FIELD_NUMBER: _ClassVar[int]
    IS_VM_FIELD_NUMBER: _ClassVar[int]
    PC_UPTIME_MS_FIELD_NUMBER: _ClassVar[int]
    AGENT_UPTIME_MS_FIELD_NUMBER: _ClassVar[int]
    SERVICE_UPTIME_MS_FIELD_NUMBER: _ClassVar[int]
    SECURITY_PRODUCTS_FIELD_NUMBER: _ClassVar[int]
    PROBE_ERRORS_FIELD_NUMBER: _ClassVar[int]
    IPV4_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    computer_name: str
    dns_hostname: str
    domain: str
    logged_on_user: str
    agent_run_as: str
    is_elevated: bool
    product_name: str
    edition_id: str
    display_version: str
    release_id: str
    build_major: int
    build_ubr: int
    full_build_string: str
    install_date: str
    boot_time: str
    timezone: str
    arch: str
    testsigning: bool
    testsigning_source: str
    hvci: bool
    hvci_source: str
    secureboot: bool
    secureboot_source: str
    kernel_debugger: bool
    kernel_debugger_source: str
    vbs_enabled: bool
    vbs_source: str
    credential_guard: bool
    credential_guard_source: str
    driver_blocklist_on: bool
    driver_blocklist_source: str
    lsa_protected: bool
    lsa_protected_source: str
    smep: bool
    smap: bool
    cet_shstk: bool
    patchguard_state: str
    kva_shadow: bool
    kva_shadow_source: str
    cpu_brand: str
    cpu_cores: int
    cpu_logical: int
    phys_mem_bytes: int
    hypervisor_vendor: str
    is_vm: bool
    pc_uptime_ms: int
    agent_uptime_ms: int
    service_uptime_ms: int
    security_products: _containers.RepeatedCompositeFieldContainer[SecurityProduct]
    probe_errors: _containers.RepeatedScalarFieldContainer[str]
    ipv4: _containers.RepeatedCompositeFieldContainer[AdapterInfo]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., computer_name: _Optional[str] = ..., dns_hostname: _Optional[str] = ..., domain: _Optional[str] = ..., logged_on_user: _Optional[str] = ..., agent_run_as: _Optional[str] = ..., is_elevated: _Optional[bool] = ..., product_name: _Optional[str] = ..., edition_id: _Optional[str] = ..., display_version: _Optional[str] = ..., release_id: _Optional[str] = ..., build_major: _Optional[int] = ..., build_ubr: _Optional[int] = ..., full_build_string: _Optional[str] = ..., install_date: _Optional[str] = ..., boot_time: _Optional[str] = ..., timezone: _Optional[str] = ..., arch: _Optional[str] = ..., testsigning: _Optional[bool] = ..., testsigning_source: _Optional[str] = ..., hvci: _Optional[bool] = ..., hvci_source: _Optional[str] = ..., secureboot: _Optional[bool] = ..., secureboot_source: _Optional[str] = ..., kernel_debugger: _Optional[bool] = ..., kernel_debugger_source: _Optional[str] = ..., vbs_enabled: _Optional[bool] = ..., vbs_source: _Optional[str] = ..., credential_guard: _Optional[bool] = ..., credential_guard_source: _Optional[str] = ..., driver_blocklist_on: _Optional[bool] = ..., driver_blocklist_source: _Optional[str] = ..., lsa_protected: _Optional[bool] = ..., lsa_protected_source: _Optional[str] = ..., smep: _Optional[bool] = ..., smap: _Optional[bool] = ..., cet_shstk: _Optional[bool] = ..., patchguard_state: _Optional[str] = ..., kva_shadow: _Optional[bool] = ..., kva_shadow_source: _Optional[str] = ..., cpu_brand: _Optional[str] = ..., cpu_cores: _Optional[int] = ..., cpu_logical: _Optional[int] = ..., phys_mem_bytes: _Optional[int] = ..., hypervisor_vendor: _Optional[str] = ..., is_vm: _Optional[bool] = ..., pc_uptime_ms: _Optional[int] = ..., agent_uptime_ms: _Optional[int] = ..., service_uptime_ms: _Optional[int] = ..., security_products: _Optional[_Iterable[_Union[SecurityProduct, _Mapping]]] = ..., probe_errors: _Optional[_Iterable[str]] = ..., ipv4: _Optional[_Iterable[_Union[AdapterInfo, _Mapping]]] = ...) -> None: ...

class NetPinStatusRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class NetPinStatusResponse(_message.Message):
    __slots__ = ("status", "enabled", "hold", "adapter", "pinned_address", "pinned_prefix", "pinned_gateway", "current_address", "last_pin_at_epoch_ms", "pin_attempts", "pin_failures_streak", "last_error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    HOLD_FIELD_NUMBER: _ClassVar[int]
    ADAPTER_FIELD_NUMBER: _ClassVar[int]
    PINNED_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    PINNED_PREFIX_FIELD_NUMBER: _ClassVar[int]
    PINNED_GATEWAY_FIELD_NUMBER: _ClassVar[int]
    CURRENT_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LAST_PIN_AT_EPOCH_MS_FIELD_NUMBER: _ClassVar[int]
    PIN_ATTEMPTS_FIELD_NUMBER: _ClassVar[int]
    PIN_FAILURES_STREAK_FIELD_NUMBER: _ClassVar[int]
    LAST_ERROR_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    enabled: bool
    hold: bool
    adapter: str
    pinned_address: str
    pinned_prefix: int
    pinned_gateway: str
    current_address: str
    last_pin_at_epoch_ms: int
    pin_attempts: int
    pin_failures_streak: int
    last_error: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., enabled: _Optional[bool] = ..., hold: _Optional[bool] = ..., adapter: _Optional[str] = ..., pinned_address: _Optional[str] = ..., pinned_prefix: _Optional[int] = ..., pinned_gateway: _Optional[str] = ..., current_address: _Optional[str] = ..., last_pin_at_epoch_ms: _Optional[int] = ..., pin_attempts: _Optional[int] = ..., pin_failures_streak: _Optional[int] = ..., last_error: _Optional[str] = ...) -> None: ...

class NetPinApplyRequest(_message.Message):
    __slots__ = ("clear_hold",)
    CLEAR_HOLD_FIELD_NUMBER: _ClassVar[int]
    clear_hold: bool
    def __init__(self, clear_hold: _Optional[bool] = ...) -> None: ...

class NetPinApplyResponse(_message.Message):
    __slots__ = ("status", "applied", "details")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    APPLIED_FIELD_NUMBER: _ClassVar[int]
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    applied: bool
    details: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., applied: _Optional[bool] = ..., details: _Optional[str] = ...) -> None: ...

class WindowRect(_message.Message):
    __slots__ = ("x", "y", "width", "height")
    X_FIELD_NUMBER: _ClassVar[int]
    Y_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    x: int
    y: int
    width: int
    height: int
    def __init__(self, x: _Optional[int] = ..., y: _Optional[int] = ..., width: _Optional[int] = ..., height: _Optional[int] = ...) -> None: ...

class WindowDetail(_message.Message):
    __slots__ = ("hwnd", "title", "rect", "is_foreground", "is_minimized", "z_order", "class_name", "client_rect", "style", "exstyle", "window_status", "border_cx", "border_cy", "show_cmd", "normal_pos", "parent", "owner", "pid", "tid", "process_path", "hinstance", "visible", "enabled", "maximized", "topmost", "layered", "tool_window", "cloaked", "dpi", "window_type_atom", "props", "children")
    HWND_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    RECT_FIELD_NUMBER: _ClassVar[int]
    IS_FOREGROUND_FIELD_NUMBER: _ClassVar[int]
    IS_MINIMIZED_FIELD_NUMBER: _ClassVar[int]
    Z_ORDER_FIELD_NUMBER: _ClassVar[int]
    CLASS_NAME_FIELD_NUMBER: _ClassVar[int]
    CLIENT_RECT_FIELD_NUMBER: _ClassVar[int]
    STYLE_FIELD_NUMBER: _ClassVar[int]
    EXSTYLE_FIELD_NUMBER: _ClassVar[int]
    WINDOW_STATUS_FIELD_NUMBER: _ClassVar[int]
    BORDER_CX_FIELD_NUMBER: _ClassVar[int]
    BORDER_CY_FIELD_NUMBER: _ClassVar[int]
    SHOW_CMD_FIELD_NUMBER: _ClassVar[int]
    NORMAL_POS_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    PROCESS_PATH_FIELD_NUMBER: _ClassVar[int]
    HINSTANCE_FIELD_NUMBER: _ClassVar[int]
    VISIBLE_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    MAXIMIZED_FIELD_NUMBER: _ClassVar[int]
    TOPMOST_FIELD_NUMBER: _ClassVar[int]
    LAYERED_FIELD_NUMBER: _ClassVar[int]
    TOOL_WINDOW_FIELD_NUMBER: _ClassVar[int]
    CLOAKED_FIELD_NUMBER: _ClassVar[int]
    DPI_FIELD_NUMBER: _ClassVar[int]
    WINDOW_TYPE_ATOM_FIELD_NUMBER: _ClassVar[int]
    PROPS_FIELD_NUMBER: _ClassVar[int]
    CHILDREN_FIELD_NUMBER: _ClassVar[int]
    hwnd: int
    title: str
    rect: WindowRect
    is_foreground: bool
    is_minimized: bool
    z_order: int
    class_name: str
    client_rect: WindowRect
    style: int
    exstyle: int
    window_status: int
    border_cx: int
    border_cy: int
    show_cmd: int
    normal_pos: WindowRect
    parent: int
    owner: int
    pid: int
    tid: int
    process_path: str
    hinstance: int
    visible: bool
    enabled: bool
    maximized: bool
    topmost: bool
    layered: bool
    tool_window: bool
    cloaked: bool
    dpi: int
    window_type_atom: int
    props: _containers.RepeatedCompositeFieldContainer[WindowProp]
    children: _containers.RepeatedCompositeFieldContainer[WindowDetail]
    def __init__(self, hwnd: _Optional[int] = ..., title: _Optional[str] = ..., rect: _Optional[_Union[WindowRect, _Mapping]] = ..., is_foreground: _Optional[bool] = ..., is_minimized: _Optional[bool] = ..., z_order: _Optional[int] = ..., class_name: _Optional[str] = ..., client_rect: _Optional[_Union[WindowRect, _Mapping]] = ..., style: _Optional[int] = ..., exstyle: _Optional[int] = ..., window_status: _Optional[int] = ..., border_cx: _Optional[int] = ..., border_cy: _Optional[int] = ..., show_cmd: _Optional[int] = ..., normal_pos: _Optional[_Union[WindowRect, _Mapping]] = ..., parent: _Optional[int] = ..., owner: _Optional[int] = ..., pid: _Optional[int] = ..., tid: _Optional[int] = ..., process_path: _Optional[str] = ..., hinstance: _Optional[int] = ..., visible: _Optional[bool] = ..., enabled: _Optional[bool] = ..., maximized: _Optional[bool] = ..., topmost: _Optional[bool] = ..., layered: _Optional[bool] = ..., tool_window: _Optional[bool] = ..., cloaked: _Optional[bool] = ..., dpi: _Optional[int] = ..., window_type_atom: _Optional[int] = ..., props: _Optional[_Iterable[_Union[WindowProp, _Mapping]]] = ..., children: _Optional[_Iterable[_Union[WindowDetail, _Mapping]]] = ...) -> None: ...

class WindowProp(_message.Message):
    __slots__ = ("name", "atom", "data")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ATOM_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    name: str
    atom: int
    data: int
    def __init__(self, name: _Optional[str] = ..., atom: _Optional[int] = ..., data: _Optional[int] = ...) -> None: ...

class ProcessWindowGroup(_message.Message):
    __slots__ = ("pid", "process_name", "windows")
    PID_FIELD_NUMBER: _ClassVar[int]
    PROCESS_NAME_FIELD_NUMBER: _ClassVar[int]
    WINDOWS_FIELD_NUMBER: _ClassVar[int]
    pid: int
    process_name: str
    windows: _containers.RepeatedCompositeFieldContainer[WindowDetail]
    def __init__(self, pid: _Optional[int] = ..., process_name: _Optional[str] = ..., windows: _Optional[_Iterable[_Union[WindowDetail, _Mapping]]] = ...) -> None: ...

class ScreenCaptureRequest(_message.Message):
    __slots__ = ("mode", "display_id", "hwnd", "pid", "window_title", "max_dimension", "format", "include_windows", "include_hidden", "include_details", "process_name", "query")
    MODE_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_ID_FIELD_NUMBER: _ClassVar[int]
    HWND_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    WINDOW_TITLE_FIELD_NUMBER: _ClassVar[int]
    MAX_DIMENSION_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_WINDOWS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_HIDDEN_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_DETAILS_FIELD_NUMBER: _ClassVar[int]
    PROCESS_NAME_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    mode: str
    display_id: str
    hwnd: int
    pid: int
    window_title: str
    max_dimension: int
    format: str
    include_windows: bool
    include_hidden: bool
    include_details: bool
    process_name: str
    query: str
    def __init__(self, mode: _Optional[str] = ..., display_id: _Optional[str] = ..., hwnd: _Optional[int] = ..., pid: _Optional[int] = ..., window_title: _Optional[str] = ..., max_dimension: _Optional[int] = ..., format: _Optional[str] = ..., include_windows: _Optional[bool] = ..., include_hidden: _Optional[bool] = ..., include_details: _Optional[bool] = ..., process_name: _Optional[str] = ..., query: _Optional[str] = ...) -> None: ...

class ScreenCaptureResponse(_message.Message):
    __slots__ = ("status", "image_data", "target_type", "target_name", "width", "height", "timestamp_unix_ms", "windows_json")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    IMAGE_DATA_FIELD_NUMBER: _ClassVar[int]
    TARGET_TYPE_FIELD_NUMBER: _ClassVar[int]
    TARGET_NAME_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    WINDOWS_JSON_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    image_data: bytes
    target_type: str
    target_name: str
    width: int
    height: int
    timestamp_unix_ms: int
    windows_json: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., image_data: _Optional[bytes] = ..., target_type: _Optional[str] = ..., target_name: _Optional[str] = ..., width: _Optional[int] = ..., height: _Optional[int] = ..., timestamp_unix_ms: _Optional[int] = ..., windows_json: _Optional[str] = ...) -> None: ...

class WindowListRequest(_message.Message):
    __slots__ = ("pid", "process_name", "query", "include_hidden", "include_details", "include_children", "include_props")
    PID_FIELD_NUMBER: _ClassVar[int]
    PROCESS_NAME_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_HIDDEN_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_DETAILS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_CHILDREN_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_PROPS_FIELD_NUMBER: _ClassVar[int]
    pid: int
    process_name: str
    query: str
    include_hidden: bool
    include_details: bool
    include_children: bool
    include_props: bool
    def __init__(self, pid: _Optional[int] = ..., process_name: _Optional[str] = ..., query: _Optional[str] = ..., include_hidden: _Optional[bool] = ..., include_details: _Optional[bool] = ..., include_children: _Optional[bool] = ..., include_props: _Optional[bool] = ...) -> None: ...

class WindowListResponse(_message.Message):
    __slots__ = ("status", "windows_json", "total_windows")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    WINDOWS_JSON_FIELD_NUMBER: _ClassVar[int]
    TOTAL_WINDOWS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    windows_json: str
    total_windows: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., windows_json: _Optional[str] = ..., total_windows: _Optional[int] = ...) -> None: ...

class ListWindowPropsRequest(_message.Message):
    __slots__ = ("hwnd", "include_values")
    HWND_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_VALUES_FIELD_NUMBER: _ClassVar[int]
    hwnd: int
    include_values: bool
    def __init__(self, hwnd: _Optional[int] = ..., include_values: _Optional[bool] = ...) -> None: ...

class ListWindowPropsResponse(_message.Message):
    __slots__ = ("status", "hwnd", "props")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HWND_FIELD_NUMBER: _ClassVar[int]
    PROPS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    hwnd: int
    props: _containers.RepeatedCompositeFieldContainer[WindowProp]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., hwnd: _Optional[int] = ..., props: _Optional[_Iterable[_Union[WindowProp, _Mapping]]] = ...) -> None: ...

class GetWindowTreeRequest(_message.Message):
    __slots__ = ("hwnd", "pid", "max_depth", "include_props")
    HWND_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    MAX_DEPTH_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_PROPS_FIELD_NUMBER: _ClassVar[int]
    hwnd: int
    pid: int
    max_depth: int
    include_props: bool
    def __init__(self, hwnd: _Optional[int] = ..., pid: _Optional[int] = ..., max_depth: _Optional[int] = ..., include_props: _Optional[bool] = ...) -> None: ...

class GetWindowTreeResponse(_message.Message):
    __slots__ = ("status", "root")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ROOT_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    root: WindowDetail
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., root: _Optional[_Union[WindowDetail, _Mapping]] = ...) -> None: ...

class RebootRequest(_message.Message):
    __slots__ = ("mode", "delay_s", "force", "force_if_hung", "reason", "reason_code", "wait_pre_shutdown")
    class Mode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        MODE_UNSPECIFIED: _ClassVar[RebootRequest.Mode]
        REBOOT: _ClassVar[RebootRequest.Mode]
        SHUTDOWN: _ClassVar[RebootRequest.Mode]
        POWEROFF: _ClassVar[RebootRequest.Mode]
        LOGOFF: _ClassVar[RebootRequest.Mode]
        ABORT: _ClassVar[RebootRequest.Mode]
    MODE_UNSPECIFIED: RebootRequest.Mode
    REBOOT: RebootRequest.Mode
    SHUTDOWN: RebootRequest.Mode
    POWEROFF: RebootRequest.Mode
    LOGOFF: RebootRequest.Mode
    ABORT: RebootRequest.Mode
    MODE_FIELD_NUMBER: _ClassVar[int]
    DELAY_S_FIELD_NUMBER: _ClassVar[int]
    FORCE_FIELD_NUMBER: _ClassVar[int]
    FORCE_IF_HUNG_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    WAIT_PRE_SHUTDOWN_FIELD_NUMBER: _ClassVar[int]
    mode: RebootRequest.Mode
    delay_s: int
    force: bool
    force_if_hung: bool
    reason: str
    reason_code: int
    wait_pre_shutdown: bool
    def __init__(self, mode: _Optional[_Union[RebootRequest.Mode, str]] = ..., delay_s: _Optional[int] = ..., force: _Optional[bool] = ..., force_if_hung: _Optional[bool] = ..., reason: _Optional[str] = ..., reason_code: _Optional[int] = ..., wait_pre_shutdown: _Optional[bool] = ...) -> None: ...

class RebootResponse(_message.Message):
    __slots__ = ("ok", "boot_epoch_ms_at_issue", "agent_instance_id_at_issue", "win32_error", "message", "mode_applied", "delay_s_applied")
    OK_FIELD_NUMBER: _ClassVar[int]
    BOOT_EPOCH_MS_AT_ISSUE_FIELD_NUMBER: _ClassVar[int]
    AGENT_INSTANCE_ID_AT_ISSUE_FIELD_NUMBER: _ClassVar[int]
    WIN32_ERROR_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    MODE_APPLIED_FIELD_NUMBER: _ClassVar[int]
    DELAY_S_APPLIED_FIELD_NUMBER: _ClassVar[int]
    ok: bool
    boot_epoch_ms_at_issue: int
    agent_instance_id_at_issue: str
    win32_error: int
    message: str
    mode_applied: int
    delay_s_applied: int
    def __init__(self, ok: _Optional[bool] = ..., boot_epoch_ms_at_issue: _Optional[int] = ..., agent_instance_id_at_issue: _Optional[str] = ..., win32_error: _Optional[int] = ..., message: _Optional[str] = ..., mode_applied: _Optional[int] = ..., delay_s_applied: _Optional[int] = ...) -> None: ...

class InputClickRequest(_message.Message):
    __slots__ = ("x", "y", "button", "action", "modifiers", "click_count", "force")
    X_FIELD_NUMBER: _ClassVar[int]
    Y_FIELD_NUMBER: _ClassVar[int]
    BUTTON_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    MODIFIERS_FIELD_NUMBER: _ClassVar[int]
    CLICK_COUNT_FIELD_NUMBER: _ClassVar[int]
    FORCE_FIELD_NUMBER: _ClassVar[int]
    x: int
    y: int
    button: InputButton
    action: InputAction
    modifiers: int
    click_count: int
    force: bool
    def __init__(self, x: _Optional[int] = ..., y: _Optional[int] = ..., button: _Optional[_Union[InputButton, str]] = ..., action: _Optional[_Union[InputAction, str]] = ..., modifiers: _Optional[int] = ..., click_count: _Optional[int] = ..., force: _Optional[bool] = ...) -> None: ...

class InputTypeRequest(_message.Message):
    __slots__ = ("text", "delay_ms", "force")
    TEXT_FIELD_NUMBER: _ClassVar[int]
    DELAY_MS_FIELD_NUMBER: _ClassVar[int]
    FORCE_FIELD_NUMBER: _ClassVar[int]
    text: str
    delay_ms: int
    force: bool
    def __init__(self, text: _Optional[str] = ..., delay_ms: _Optional[int] = ..., force: _Optional[bool] = ...) -> None: ...

class InputKeyRequest(_message.Message):
    __slots__ = ("key", "action", "repeat", "force")
    KEY_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    REPEAT_FIELD_NUMBER: _ClassVar[int]
    FORCE_FIELD_NUMBER: _ClassVar[int]
    key: str
    action: InputAction
    repeat: int
    force: bool
    def __init__(self, key: _Optional[str] = ..., action: _Optional[_Union[InputAction, str]] = ..., repeat: _Optional[int] = ..., force: _Optional[bool] = ...) -> None: ...

class InputResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ...) -> None: ...

class MemoryReadRequest(_message.Message):
    __slots__ = ("pid", "address", "size", "space", "addr_width", "allow_fault", "partial", "allow_mmio", "max_bytes")
    PID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    ADDR_WIDTH_FIELD_NUMBER: _ClassVar[int]
    ALLOW_FAULT_FIELD_NUMBER: _ClassVar[int]
    PARTIAL_FIELD_NUMBER: _ClassVar[int]
    ALLOW_MMIO_FIELD_NUMBER: _ClassVar[int]
    MAX_BYTES_FIELD_NUMBER: _ClassVar[int]
    pid: int
    address: int
    size: int
    space: MemSpace
    addr_width: int
    allow_fault: bool
    partial: bool
    allow_mmio: bool
    max_bytes: int
    def __init__(self, pid: _Optional[int] = ..., address: _Optional[int] = ..., size: _Optional[int] = ..., space: _Optional[_Union[MemSpace, str]] = ..., addr_width: _Optional[int] = ..., allow_fault: _Optional[bool] = ..., partial: _Optional[bool] = ..., allow_mmio: _Optional[bool] = ..., max_bytes: _Optional[int] = ...) -> None: ...

class MemoryReadResponse(_message.Message):
    __slots__ = ("status", "data", "read_bytes", "first_bad_offset")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    READ_BYTES_FIELD_NUMBER: _ClassVar[int]
    FIRST_BAD_OFFSET_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    data: bytes
    read_bytes: int
    first_bad_offset: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., data: _Optional[bytes] = ..., read_bytes: _Optional[int] = ..., first_bad_offset: _Optional[int] = ...) -> None: ...

class MemoryWriteRequest(_message.Message):
    __slots__ = ("pid", "address", "data", "space", "addr_width", "allow_map_write", "cr3", "flags")
    PID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    ADDR_WIDTH_FIELD_NUMBER: _ClassVar[int]
    ALLOW_MAP_WRITE_FIELD_NUMBER: _ClassVar[int]
    CR3_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    pid: int
    address: int
    data: bytes
    space: MemSpace
    addr_width: int
    allow_map_write: bool
    cr3: int
    flags: int
    def __init__(self, pid: _Optional[int] = ..., address: _Optional[int] = ..., data: _Optional[bytes] = ..., space: _Optional[_Union[MemSpace, str]] = ..., addr_width: _Optional[int] = ..., allow_map_write: _Optional[bool] = ..., cr3: _Optional[int] = ..., flags: _Optional[int] = ...) -> None: ...

class MemoryWriteResponse(_message.Message):
    __slots__ = ("status", "written_bytes", "write_path")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    WRITTEN_BYTES_FIELD_NUMBER: _ClassVar[int]
    WRITE_PATH_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    written_bytes: int
    write_path: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., written_bytes: _Optional[int] = ..., write_path: _Optional[int] = ...) -> None: ...

class MemoryAllocRequest(_message.Message):
    __slots__ = ("pid", "kernel", "size", "protect", "addr_width")
    PID_FIELD_NUMBER: _ClassVar[int]
    KERNEL_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    PROTECT_FIELD_NUMBER: _ClassVar[int]
    ADDR_WIDTH_FIELD_NUMBER: _ClassVar[int]
    pid: int
    kernel: bool
    size: int
    protect: int
    addr_width: int
    def __init__(self, pid: _Optional[int] = ..., kernel: _Optional[bool] = ..., size: _Optional[int] = ..., protect: _Optional[int] = ..., addr_width: _Optional[int] = ...) -> None: ...

class MemoryAllocResponse(_message.Message):
    __slots__ = ("status", "address")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    address: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., address: _Optional[int] = ...) -> None: ...

class MemoryFreeRequest(_message.Message):
    __slots__ = ("pid", "kernel", "address")
    PID_FIELD_NUMBER: _ClassVar[int]
    KERNEL_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    pid: int
    kernel: bool
    address: int
    def __init__(self, pid: _Optional[int] = ..., kernel: _Optional[bool] = ..., address: _Optional[int] = ...) -> None: ...

class MemoryFreeResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ...) -> None: ...

class MemoryProtectRequest(_message.Message):
    __slots__ = ("pid", "address", "size", "protect", "addr_width")
    PID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    PROTECT_FIELD_NUMBER: _ClassVar[int]
    ADDR_WIDTH_FIELD_NUMBER: _ClassVar[int]
    pid: int
    address: int
    size: int
    protect: int
    addr_width: int
    def __init__(self, pid: _Optional[int] = ..., address: _Optional[int] = ..., size: _Optional[int] = ..., protect: _Optional[int] = ..., addr_width: _Optional[int] = ...) -> None: ...

class MemoryProtectResponse(_message.Message):
    __slots__ = ("status", "old_protect")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    OLD_PROTECT_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    old_protect: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., old_protect: _Optional[int] = ...) -> None: ...

class ModuleInfo(_message.Message):
    __slots__ = ("name", "path", "base", "size", "kernel")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    BASE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    KERNEL_FIELD_NUMBER: _ClassVar[int]
    name: str
    path: str
    base: int
    size: int
    kernel: bool
    def __init__(self, name: _Optional[str] = ..., path: _Optional[str] = ..., base: _Optional[int] = ..., size: _Optional[int] = ..., kernel: _Optional[bool] = ...) -> None: ...

class ModulesRequest(_message.Message):
    __slots__ = ("pid", "kernel", "limit", "offset")
    PID_FIELD_NUMBER: _ClassVar[int]
    KERNEL_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    pid: int
    kernel: bool
    limit: int
    offset: int
    def __init__(self, pid: _Optional[int] = ..., kernel: _Optional[bool] = ..., limit: _Optional[int] = ..., offset: _Optional[int] = ...) -> None: ...

class ModulesResponse(_message.Message):
    __slots__ = ("status", "modules")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MODULES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    modules: _containers.RepeatedCompositeFieldContainer[ModuleInfo]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., modules: _Optional[_Iterable[_Union[ModuleInfo, _Mapping]]] = ...) -> None: ...

class PatternScanRequest(_message.Message):
    __slots__ = ("pid", "base", "size", "pattern", "mask", "space", "max_results")
    PID_FIELD_NUMBER: _ClassVar[int]
    BASE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    MASK_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    MAX_RESULTS_FIELD_NUMBER: _ClassVar[int]
    pid: int
    base: int
    size: int
    pattern: bytes
    mask: str
    space: MemSpace
    max_results: int
    def __init__(self, pid: _Optional[int] = ..., base: _Optional[int] = ..., size: _Optional[int] = ..., pattern: _Optional[bytes] = ..., mask: _Optional[str] = ..., space: _Optional[_Union[MemSpace, str]] = ..., max_results: _Optional[int] = ...) -> None: ...

class PatternScanResponse(_message.Message):
    __slots__ = ("status", "addresses")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    addresses: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., addresses: _Optional[_Iterable[int]] = ...) -> None: ...

class PatternScanChunk(_message.Message):
    __slots__ = ("status", "addresses", "bytes_scanned", "cursor", "done")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    BYTES_SCANNED_FIELD_NUMBER: _ClassVar[int]
    CURSOR_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    addresses: _containers.RepeatedScalarFieldContainer[int]
    bytes_scanned: int
    cursor: int
    done: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., addresses: _Optional[_Iterable[int]] = ..., bytes_scanned: _Optional[int] = ..., cursor: _Optional[int] = ..., done: _Optional[bool] = ...) -> None: ...

class VadEntry(_message.Message):
    __slots__ = ("start", "end", "protect", "vad_type", "commit_charge")
    START_FIELD_NUMBER: _ClassVar[int]
    END_FIELD_NUMBER: _ClassVar[int]
    PROTECT_FIELD_NUMBER: _ClassVar[int]
    VAD_TYPE_FIELD_NUMBER: _ClassVar[int]
    COMMIT_CHARGE_FIELD_NUMBER: _ClassVar[int]
    start: int
    end: int
    protect: int
    vad_type: int
    commit_charge: int
    def __init__(self, start: _Optional[int] = ..., end: _Optional[int] = ..., protect: _Optional[int] = ..., vad_type: _Optional[int] = ..., commit_charge: _Optional[int] = ...) -> None: ...

class VadRequest(_message.Message):
    __slots__ = ("pid", "limit", "offset")
    PID_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    pid: int
    limit: int
    offset: int
    def __init__(self, pid: _Optional[int] = ..., limit: _Optional[int] = ..., offset: _Optional[int] = ...) -> None: ...

class VadResponse(_message.Message):
    __slots__ = ("status", "entries")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    entries: _containers.RepeatedCompositeFieldContainer[VadEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., entries: _Optional[_Iterable[_Union[VadEntry, _Mapping]]] = ...) -> None: ...

class HandleEntry(_message.Message):
    __slots__ = ("object", "handle", "granted_access", "type_index", "type_name", "name")
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    HANDLE_FIELD_NUMBER: _ClassVar[int]
    GRANTED_ACCESS_FIELD_NUMBER: _ClassVar[int]
    TYPE_INDEX_FIELD_NUMBER: _ClassVar[int]
    TYPE_NAME_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    object: int
    handle: int
    granted_access: int
    type_index: int
    type_name: str
    name: str
    def __init__(self, object: _Optional[int] = ..., handle: _Optional[int] = ..., granted_access: _Optional[int] = ..., type_index: _Optional[int] = ..., type_name: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class HandleListRequest(_message.Message):
    __slots__ = ("pid", "want_names", "limit", "offset")
    PID_FIELD_NUMBER: _ClassVar[int]
    WANT_NAMES_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    pid: int
    want_names: bool
    limit: int
    offset: int
    def __init__(self, pid: _Optional[int] = ..., want_names: _Optional[bool] = ..., limit: _Optional[int] = ..., offset: _Optional[int] = ...) -> None: ...

class HandleListResponse(_message.Message):
    __slots__ = ("status", "handles")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HANDLES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    handles: _containers.RepeatedCompositeFieldContainer[HandleEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., handles: _Optional[_Iterable[_Union[HandleEntry, _Mapping]]] = ...) -> None: ...

class ProcessInfo(_message.Message):
    __slots__ = ("pid", "parent_pid", "image_name", "cmdline", "create_time_100ns", "session_id")
    PID_FIELD_NUMBER: _ClassVar[int]
    PARENT_PID_FIELD_NUMBER: _ClassVar[int]
    IMAGE_NAME_FIELD_NUMBER: _ClassVar[int]
    CMDLINE_FIELD_NUMBER: _ClassVar[int]
    CREATE_TIME_100NS_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    pid: int
    parent_pid: int
    image_name: str
    cmdline: str
    create_time_100ns: int
    session_id: int
    def __init__(self, pid: _Optional[int] = ..., parent_pid: _Optional[int] = ..., image_name: _Optional[str] = ..., cmdline: _Optional[str] = ..., create_time_100ns: _Optional[int] = ..., session_id: _Optional[int] = ...) -> None: ...

class ListProcessesRequest(_message.Message):
    __slots__ = ("limit", "offset", "with_cmdline")
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    WITH_CMDLINE_FIELD_NUMBER: _ClassVar[int]
    limit: int
    offset: int
    with_cmdline: bool
    def __init__(self, limit: _Optional[int] = ..., offset: _Optional[int] = ..., with_cmdline: _Optional[bool] = ...) -> None: ...

class ListProcessesResponse(_message.Message):
    __slots__ = ("status", "processes", "source")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PROCESSES_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    processes: _containers.RepeatedCompositeFieldContainer[ProcessInfo]
    source: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., processes: _Optional[_Iterable[_Union[ProcessInfo, _Mapping]]] = ..., source: _Optional[str] = ...) -> None: ...

class IatEntry(_message.Message):
    __slots__ = ("dll", "name", "ordinal", "iat_slot", "resolved", "resolved_module", "hooked")
    DLL_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ORDINAL_FIELD_NUMBER: _ClassVar[int]
    IAT_SLOT_FIELD_NUMBER: _ClassVar[int]
    RESOLVED_FIELD_NUMBER: _ClassVar[int]
    RESOLVED_MODULE_FIELD_NUMBER: _ClassVar[int]
    HOOKED_FIELD_NUMBER: _ClassVar[int]
    dll: str
    name: str
    ordinal: int
    iat_slot: int
    resolved: int
    resolved_module: str
    hooked: bool
    def __init__(self, dll: _Optional[str] = ..., name: _Optional[str] = ..., ordinal: _Optional[int] = ..., iat_slot: _Optional[int] = ..., resolved: _Optional[int] = ..., resolved_module: _Optional[str] = ..., hooked: _Optional[bool] = ...) -> None: ...

class ModuleImportsRequest(_message.Message):
    __slots__ = ("pid", "module", "kernel", "limit", "offset")
    PID_FIELD_NUMBER: _ClassVar[int]
    MODULE_FIELD_NUMBER: _ClassVar[int]
    KERNEL_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    pid: int
    module: str
    kernel: bool
    limit: int
    offset: int
    def __init__(self, pid: _Optional[int] = ..., module: _Optional[str] = ..., kernel: _Optional[bool] = ..., limit: _Optional[int] = ..., offset: _Optional[int] = ...) -> None: ...

class ModuleImportsResponse(_message.Message):
    __slots__ = ("status", "entries")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    entries: _containers.RepeatedCompositeFieldContainer[IatEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., entries: _Optional[_Iterable[_Union[IatEntry, _Mapping]]] = ...) -> None: ...

class ExportEntry(_message.Message):
    __slots__ = ("name", "ordinal", "rva", "address", "forwarder")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ORDINAL_FIELD_NUMBER: _ClassVar[int]
    RVA_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    FORWARDER_FIELD_NUMBER: _ClassVar[int]
    name: str
    ordinal: int
    rva: int
    address: int
    forwarder: str
    def __init__(self, name: _Optional[str] = ..., ordinal: _Optional[int] = ..., rva: _Optional[int] = ..., address: _Optional[int] = ..., forwarder: _Optional[str] = ...) -> None: ...

class ModuleExportsRequest(_message.Message):
    __slots__ = ("pid", "module", "kernel", "limit", "offset")
    PID_FIELD_NUMBER: _ClassVar[int]
    MODULE_FIELD_NUMBER: _ClassVar[int]
    KERNEL_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    pid: int
    module: str
    kernel: bool
    limit: int
    offset: int
    def __init__(self, pid: _Optional[int] = ..., module: _Optional[str] = ..., kernel: _Optional[bool] = ..., limit: _Optional[int] = ..., offset: _Optional[int] = ...) -> None: ...

class ModuleExportsResponse(_message.Message):
    __slots__ = ("status", "entries")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    entries: _containers.RepeatedCompositeFieldContainer[ExportEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., entries: _Optional[_Iterable[_Union[ExportEntry, _Mapping]]] = ...) -> None: ...

class HeapBlock(_message.Message):
    __slots__ = ("address", "size", "flags")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    address: int
    size: int
    flags: int
    def __init__(self, address: _Optional[int] = ..., size: _Optional[int] = ..., flags: _Optional[int] = ...) -> None: ...

class HeapEntry(_message.Message):
    __slots__ = ("handle", "flags", "base", "committed", "reserved", "blocks")
    HANDLE_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    BASE_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_FIELD_NUMBER: _ClassVar[int]
    RESERVED_FIELD_NUMBER: _ClassVar[int]
    BLOCKS_FIELD_NUMBER: _ClassVar[int]
    handle: int
    flags: int
    base: int
    committed: int
    reserved: int
    blocks: _containers.RepeatedCompositeFieldContainer[HeapBlock]
    def __init__(self, handle: _Optional[int] = ..., flags: _Optional[int] = ..., base: _Optional[int] = ..., committed: _Optional[int] = ..., reserved: _Optional[int] = ..., blocks: _Optional[_Iterable[_Union[HeapBlock, _Mapping]]] = ...) -> None: ...

class HeapListRequest(_message.Message):
    __slots__ = ("pid", "want_blocks", "max_blocks")
    PID_FIELD_NUMBER: _ClassVar[int]
    WANT_BLOCKS_FIELD_NUMBER: _ClassVar[int]
    MAX_BLOCKS_FIELD_NUMBER: _ClassVar[int]
    pid: int
    want_blocks: bool
    max_blocks: int
    def __init__(self, pid: _Optional[int] = ..., want_blocks: _Optional[bool] = ..., max_blocks: _Optional[int] = ...) -> None: ...

class HeapListResponse(_message.Message):
    __slots__ = ("status", "heaps")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HEAPS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    heaps: _containers.RepeatedCompositeFieldContainer[HeapEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., heaps: _Optional[_Iterable[_Union[HeapEntry, _Mapping]]] = ...) -> None: ...

class PhysRangesRequest(_message.Message):
    __slots__ = ("limit", "offset")
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    limit: int
    offset: int
    def __init__(self, limit: _Optional[int] = ..., offset: _Optional[int] = ...) -> None: ...

class PhysRangeEntry(_message.Message):
    __slots__ = ("base", "size", "kind")
    BASE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    base: int
    size: int
    kind: int
    def __init__(self, base: _Optional[int] = ..., size: _Optional[int] = ..., kind: _Optional[int] = ...) -> None: ...

class PhysRangesResponse(_message.Message):
    __slots__ = ("status", "ranges")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RANGES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    ranges: _containers.RepeatedCompositeFieldContainer[PhysRangeEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., ranges: _Optional[_Iterable[_Union[PhysRangeEntry, _Mapping]]] = ...) -> None: ...

class PoolScanRequest(_message.Message):
    __slots__ = ("tag_filter", "nonpaged_only", "paged_only", "max_results", "pattern", "mask", "offset", "content_span", "cursor")
    TAG_FILTER_FIELD_NUMBER: _ClassVar[int]
    NONPAGED_ONLY_FIELD_NUMBER: _ClassVar[int]
    PAGED_ONLY_FIELD_NUMBER: _ClassVar[int]
    MAX_RESULTS_FIELD_NUMBER: _ClassVar[int]
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    MASK_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    CONTENT_SPAN_FIELD_NUMBER: _ClassVar[int]
    CURSOR_FIELD_NUMBER: _ClassVar[int]
    tag_filter: int
    nonpaged_only: bool
    paged_only: bool
    max_results: int
    pattern: bytes
    mask: bytes
    offset: int
    content_span: int
    cursor: int
    def __init__(self, tag_filter: _Optional[int] = ..., nonpaged_only: _Optional[bool] = ..., paged_only: _Optional[bool] = ..., max_results: _Optional[int] = ..., pattern: _Optional[bytes] = ..., mask: _Optional[bytes] = ..., offset: _Optional[int] = ..., content_span: _Optional[int] = ..., cursor: _Optional[int] = ...) -> None: ...

class PoolBlock(_message.Message):
    __slots__ = ("virtual_address", "size_in_bytes", "tag", "tag_ascii", "nonpaged", "matched_offset")
    VIRTUAL_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SIZE_IN_BYTES_FIELD_NUMBER: _ClassVar[int]
    TAG_FIELD_NUMBER: _ClassVar[int]
    TAG_ASCII_FIELD_NUMBER: _ClassVar[int]
    NONPAGED_FIELD_NUMBER: _ClassVar[int]
    MATCHED_OFFSET_FIELD_NUMBER: _ClassVar[int]
    virtual_address: int
    size_in_bytes: int
    tag: int
    tag_ascii: str
    nonpaged: bool
    matched_offset: int
    def __init__(self, virtual_address: _Optional[int] = ..., size_in_bytes: _Optional[int] = ..., tag: _Optional[int] = ..., tag_ascii: _Optional[str] = ..., nonpaged: _Optional[bool] = ..., matched_offset: _Optional[int] = ...) -> None: ...

class PoolScanResponse(_message.Message):
    __slots__ = ("status", "entries", "required", "considered", "holes", "span_truncated", "last_index", "next_cursor")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    CONSIDERED_FIELD_NUMBER: _ClassVar[int]
    HOLES_FIELD_NUMBER: _ClassVar[int]
    SPAN_TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    LAST_INDEX_FIELD_NUMBER: _ClassVar[int]
    NEXT_CURSOR_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    entries: _containers.RepeatedCompositeFieldContainer[PoolBlock]
    required: int
    considered: int
    holes: int
    span_truncated: int
    last_index: int
    next_cursor: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., entries: _Optional[_Iterable[_Union[PoolBlock, _Mapping]]] = ..., required: _Optional[int] = ..., considered: _Optional[int] = ..., holes: _Optional[int] = ..., span_truncated: _Optional[int] = ..., last_index: _Optional[int] = ..., next_cursor: _Optional[int] = ...) -> None: ...

class MemoryReadChunk(_message.Message):
    __slots__ = ("status", "offset", "data", "eof")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    EOF_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    offset: int
    data: bytes
    eof: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., offset: _Optional[int] = ..., data: _Optional[bytes] = ..., eof: _Optional[bool] = ...) -> None: ...

class VaTranslateRequest(_message.Message):
    __slots__ = ("space", "pid", "va", "cr3")
    SPACE_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    VA_FIELD_NUMBER: _ClassVar[int]
    CR3_FIELD_NUMBER: _ClassVar[int]
    space: MemSpace
    pid: int
    va: int
    cr3: int
    def __init__(self, space: _Optional[_Union[MemSpace, str]] = ..., pid: _Optional[int] = ..., va: _Optional[int] = ..., cr3: _Optional[int] = ...) -> None: ...

class VaTranslateResponse(_message.Message):
    __slots__ = ("status", "pa", "present", "cr3", "page_size_shift")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PA_FIELD_NUMBER: _ClassVar[int]
    PRESENT_FIELD_NUMBER: _ClassVar[int]
    CR3_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_SHIFT_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    pa: int
    present: bool
    cr3: int
    page_size_shift: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., pa: _Optional[int] = ..., present: _Optional[bool] = ..., cr3: _Optional[int] = ..., page_size_shift: _Optional[int] = ...) -> None: ...

class IdtListRequest(_message.Message):
    __slots__ = ("all_cpus",)
    ALL_CPUS_FIELD_NUMBER: _ClassVar[int]
    all_cpus: bool
    def __init__(self, all_cpus: _Optional[bool] = ...) -> None: ...

class IdtEntryRow(_message.Message):
    __slots__ = ("cpu", "vector", "handler_va", "selector", "ist", "dpl", "idt_base")
    CPU_FIELD_NUMBER: _ClassVar[int]
    VECTOR_FIELD_NUMBER: _ClassVar[int]
    HANDLER_VA_FIELD_NUMBER: _ClassVar[int]
    SELECTOR_FIELD_NUMBER: _ClassVar[int]
    IST_FIELD_NUMBER: _ClassVar[int]
    DPL_FIELD_NUMBER: _ClassVar[int]
    IDT_BASE_FIELD_NUMBER: _ClassVar[int]
    cpu: int
    vector: int
    handler_va: int
    selector: int
    ist: int
    dpl: int
    idt_base: int
    def __init__(self, cpu: _Optional[int] = ..., vector: _Optional[int] = ..., handler_va: _Optional[int] = ..., selector: _Optional[int] = ..., ist: _Optional[int] = ..., dpl: _Optional[int] = ..., idt_base: _Optional[int] = ...) -> None: ...

class IdtListResponse(_message.Message):
    __slots__ = ("status", "idt_base", "idt_limit", "entries")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    IDT_BASE_FIELD_NUMBER: _ClassVar[int]
    IDT_LIMIT_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    idt_base: int
    idt_limit: int
    entries: _containers.RepeatedCompositeFieldContainer[IdtEntryRow]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., idt_base: _Optional[int] = ..., idt_limit: _Optional[int] = ..., entries: _Optional[_Iterable[_Union[IdtEntryRow, _Mapping]]] = ...) -> None: ...

class WatchRequest(_message.Message):
    __slots__ = ("space", "pid", "address", "length", "interval_ms", "duration_s", "expected_hex", "max_events", "tag")
    SPACE_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    INTERVAL_MS_FIELD_NUMBER: _ClassVar[int]
    DURATION_S_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_HEX_FIELD_NUMBER: _ClassVar[int]
    MAX_EVENTS_FIELD_NUMBER: _ClassVar[int]
    TAG_FIELD_NUMBER: _ClassVar[int]
    space: MemSpace
    pid: int
    address: int
    length: int
    interval_ms: int
    duration_s: int
    expected_hex: bytes
    max_events: int
    tag: str
    def __init__(self, space: _Optional[_Union[MemSpace, str]] = ..., pid: _Optional[int] = ..., address: _Optional[int] = ..., length: _Optional[int] = ..., interval_ms: _Optional[int] = ..., duration_s: _Optional[int] = ..., expected_hex: _Optional[bytes] = ..., max_events: _Optional[int] = ..., tag: _Optional[str] = ...) -> None: ...

class WatchEvent(_message.Message):
    __slots__ = ("status", "seq", "ts_ms", "prev", "now", "eof", "reason", "read_failed")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SEQ_FIELD_NUMBER: _ClassVar[int]
    TS_MS_FIELD_NUMBER: _ClassVar[int]
    PREV_FIELD_NUMBER: _ClassVar[int]
    NOW_FIELD_NUMBER: _ClassVar[int]
    EOF_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    READ_FAILED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    seq: int
    ts_ms: int
    prev: bytes
    now: bytes
    eof: bool
    reason: str
    read_failed: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., seq: _Optional[int] = ..., ts_ms: _Optional[int] = ..., prev: _Optional[bytes] = ..., now: _Optional[bytes] = ..., eof: _Optional[bool] = ..., reason: _Optional[str] = ..., read_failed: _Optional[bool] = ...) -> None: ...

class HeapAttribRequest(_message.Message):
    __slots__ = ("pid", "vas", "refresh")
    PID_FIELD_NUMBER: _ClassVar[int]
    VAS_FIELD_NUMBER: _ClassVar[int]
    REFRESH_FIELD_NUMBER: _ClassVar[int]
    pid: int
    vas: _containers.RepeatedScalarFieldContainer[int]
    refresh: bool
    def __init__(self, pid: _Optional[int] = ..., vas: _Optional[_Iterable[int]] = ..., refresh: _Optional[bool] = ...) -> None: ...

class HeapAttribRecord(_message.Message):
    __slots__ = ("va", "found", "heap_handle", "segment_base", "chunk_base", "chunk_size", "flags", "size_class")
    VA_FIELD_NUMBER: _ClassVar[int]
    FOUND_FIELD_NUMBER: _ClassVar[int]
    HEAP_HANDLE_FIELD_NUMBER: _ClassVar[int]
    SEGMENT_BASE_FIELD_NUMBER: _ClassVar[int]
    CHUNK_BASE_FIELD_NUMBER: _ClassVar[int]
    CHUNK_SIZE_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    SIZE_CLASS_FIELD_NUMBER: _ClassVar[int]
    va: int
    found: bool
    heap_handle: int
    segment_base: int
    chunk_base: int
    chunk_size: int
    flags: int
    size_class: int
    def __init__(self, va: _Optional[int] = ..., found: _Optional[bool] = ..., heap_handle: _Optional[int] = ..., segment_base: _Optional[int] = ..., chunk_base: _Optional[int] = ..., chunk_size: _Optional[int] = ..., flags: _Optional[int] = ..., size_class: _Optional[int] = ...) -> None: ...

class HeapAttribResponse(_message.Message):
    __slots__ = ("status", "records", "index_from_cache", "cache_epoch", "cache_age_ms", "cache_committed_sum")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    INDEX_FROM_CACHE_FIELD_NUMBER: _ClassVar[int]
    CACHE_EPOCH_FIELD_NUMBER: _ClassVar[int]
    CACHE_AGE_MS_FIELD_NUMBER: _ClassVar[int]
    CACHE_COMMITTED_SUM_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    records: _containers.RepeatedCompositeFieldContainer[HeapAttribRecord]
    index_from_cache: bool
    cache_epoch: int
    cache_age_ms: int
    cache_committed_sum: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., records: _Optional[_Iterable[_Union[HeapAttribRecord, _Mapping]]] = ..., index_from_cache: _Optional[bool] = ..., cache_epoch: _Optional[int] = ..., cache_age_ms: _Optional[int] = ..., cache_committed_sum: _Optional[int] = ...) -> None: ...

class HeapInfoRequest(_message.Message):
    __slots__ = ("pid", "heap_filter", "include_segments", "include_lfh_buckets")
    PID_FIELD_NUMBER: _ClassVar[int]
    HEAP_FILTER_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_SEGMENTS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_LFH_BUCKETS_FIELD_NUMBER: _ClassVar[int]
    pid: int
    heap_filter: int
    include_segments: bool
    include_lfh_buckets: bool
    def __init__(self, pid: _Optional[int] = ..., heap_filter: _Optional[int] = ..., include_segments: _Optional[bool] = ..., include_lfh_buckets: _Optional[bool] = ...) -> None: ...

class HeapInfoSegment(_message.Message):
    __slots__ = ("va", "kind", "committed", "reserved", "descriptors_count")
    VA_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_FIELD_NUMBER: _ClassVar[int]
    RESERVED_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTORS_COUNT_FIELD_NUMBER: _ClassVar[int]
    va: int
    kind: str
    committed: int
    reserved: int
    descriptors_count: int
    def __init__(self, va: _Optional[int] = ..., kind: _Optional[str] = ..., committed: _Optional[int] = ..., reserved: _Optional[int] = ..., descriptors_count: _Optional[int] = ...) -> None: ...

class HeapInfoEntry(_message.Message):
    __slots__ = ("handle", "heap_class", "size_type", "front_end_type", "lock_status", "class_name", "global_flags", "total_reserved_pages", "total_committed_pages", "segments", "warnings")
    HANDLE_FIELD_NUMBER: _ClassVar[int]
    HEAP_CLASS_FIELD_NUMBER: _ClassVar[int]
    SIZE_TYPE_FIELD_NUMBER: _ClassVar[int]
    FRONT_END_TYPE_FIELD_NUMBER: _ClassVar[int]
    LOCK_STATUS_FIELD_NUMBER: _ClassVar[int]
    CLASS_NAME_FIELD_NUMBER: _ClassVar[int]
    GLOBAL_FLAGS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_RESERVED_PAGES_FIELD_NUMBER: _ClassVar[int]
    TOTAL_COMMITTED_PAGES_FIELD_NUMBER: _ClassVar[int]
    SEGMENTS_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    handle: int
    heap_class: str
    size_type: str
    front_end_type: str
    lock_status: str
    class_name: str
    global_flags: int
    total_reserved_pages: int
    total_committed_pages: int
    segments: _containers.RepeatedCompositeFieldContainer[HeapInfoSegment]
    warnings: str
    def __init__(self, handle: _Optional[int] = ..., heap_class: _Optional[str] = ..., size_type: _Optional[str] = ..., front_end_type: _Optional[str] = ..., lock_status: _Optional[str] = ..., class_name: _Optional[str] = ..., global_flags: _Optional[int] = ..., total_reserved_pages: _Optional[int] = ..., total_committed_pages: _Optional[int] = ..., segments: _Optional[_Iterable[_Union[HeapInfoSegment, _Mapping]]] = ..., warnings: _Optional[str] = ...) -> None: ...

class HeapInfoResponse(_message.Message):
    __slots__ = ("status", "heaps", "coverage", "hint")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HEAPS_FIELD_NUMBER: _ClassVar[int]
    COVERAGE_FIELD_NUMBER: _ClassVar[int]
    HINT_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    heaps: _containers.RepeatedCompositeFieldContainer[HeapInfoEntry]
    coverage: str
    hint: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., heaps: _Optional[_Iterable[_Union[HeapInfoEntry, _Mapping]]] = ..., coverage: _Optional[str] = ..., hint: _Optional[str] = ...) -> None: ...

class Registers(_message.Message):
    __slots__ = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7", "gs_base_low", "fs_base", "gs_base")
    RAX_FIELD_NUMBER: _ClassVar[int]
    RCX_FIELD_NUMBER: _ClassVar[int]
    RDX_FIELD_NUMBER: _ClassVar[int]
    RBX_FIELD_NUMBER: _ClassVar[int]
    RSP_FIELD_NUMBER: _ClassVar[int]
    RBP_FIELD_NUMBER: _ClassVar[int]
    RSI_FIELD_NUMBER: _ClassVar[int]
    RDI_FIELD_NUMBER: _ClassVar[int]
    R8_FIELD_NUMBER: _ClassVar[int]
    R9_FIELD_NUMBER: _ClassVar[int]
    R10_FIELD_NUMBER: _ClassVar[int]
    R11_FIELD_NUMBER: _ClassVar[int]
    R12_FIELD_NUMBER: _ClassVar[int]
    R13_FIELD_NUMBER: _ClassVar[int]
    R14_FIELD_NUMBER: _ClassVar[int]
    R15_FIELD_NUMBER: _ClassVar[int]
    RIP_FIELD_NUMBER: _ClassVar[int]
    RFLAGS_FIELD_NUMBER: _ClassVar[int]
    DR0_FIELD_NUMBER: _ClassVar[int]
    DR1_FIELD_NUMBER: _ClassVar[int]
    DR2_FIELD_NUMBER: _ClassVar[int]
    DR3_FIELD_NUMBER: _ClassVar[int]
    DR6_FIELD_NUMBER: _ClassVar[int]
    DR7_FIELD_NUMBER: _ClassVar[int]
    GS_BASE_LOW_FIELD_NUMBER: _ClassVar[int]
    FS_BASE_FIELD_NUMBER: _ClassVar[int]
    GS_BASE_FIELD_NUMBER: _ClassVar[int]
    rax: int
    rcx: int
    rdx: int
    rbx: int
    rsp: int
    rbp: int
    rsi: int
    rdi: int
    r8: int
    r9: int
    r10: int
    r11: int
    r12: int
    r13: int
    r14: int
    r15: int
    rip: int
    rflags: int
    dr0: int
    dr1: int
    dr2: int
    dr3: int
    dr6: int
    dr7: int
    gs_base_low: int
    fs_base: int
    gs_base: int
    def __init__(self, rax: _Optional[int] = ..., rcx: _Optional[int] = ..., rdx: _Optional[int] = ..., rbx: _Optional[int] = ..., rsp: _Optional[int] = ..., rbp: _Optional[int] = ..., rsi: _Optional[int] = ..., rdi: _Optional[int] = ..., r8: _Optional[int] = ..., r9: _Optional[int] = ..., r10: _Optional[int] = ..., r11: _Optional[int] = ..., r12: _Optional[int] = ..., r13: _Optional[int] = ..., r14: _Optional[int] = ..., r15: _Optional[int] = ..., rip: _Optional[int] = ..., rflags: _Optional[int] = ..., dr0: _Optional[int] = ..., dr1: _Optional[int] = ..., dr2: _Optional[int] = ..., dr3: _Optional[int] = ..., dr6: _Optional[int] = ..., dr7: _Optional[int] = ..., gs_base_low: _Optional[int] = ..., fs_base: _Optional[int] = ..., gs_base: _Optional[int] = ...) -> None: ...

class StepRequest(_message.Message):
    __slots__ = ("kind", "count", "include_context")
    class Kind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        STEP_INTO: _ClassVar[StepRequest.Kind]
        STEP_OVER: _ClassVar[StepRequest.Kind]
    STEP_INTO: StepRequest.Kind
    STEP_OVER: StepRequest.Kind
    KIND_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    kind: StepRequest.Kind
    count: int
    include_context: bool
    def __init__(self, kind: _Optional[_Union[StepRequest.Kind, str]] = ..., count: _Optional[int] = ..., include_context: _Optional[bool] = ...) -> None: ...

class StepResponse(_message.Message):
    __slots__ = ("status", "state")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    state: StopInfo
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., state: _Optional[_Union[StopInfo, _Mapping]] = ...) -> None: ...

class GetRegsRequest(_message.Message):
    __slots__ = ("tid",)
    TID_FIELD_NUMBER: _ClassVar[int]
    tid: int
    def __init__(self, tid: _Optional[int] = ...) -> None: ...

class GetRegsResponse(_message.Message):
    __slots__ = ("status", "regs", "warnings")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REGS_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    regs: Registers
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., regs: _Optional[_Union[Registers, _Mapping]] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class SetRegsRequest(_message.Message):
    __slots__ = ("regs", "apply_rip", "apply_rflags", "apply_dr", "apply_gprs", "tid")
    REGS_FIELD_NUMBER: _ClassVar[int]
    APPLY_RIP_FIELD_NUMBER: _ClassVar[int]
    APPLY_RFLAGS_FIELD_NUMBER: _ClassVar[int]
    APPLY_DR_FIELD_NUMBER: _ClassVar[int]
    APPLY_GPRS_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    regs: Registers
    apply_rip: bool
    apply_rflags: bool
    apply_dr: bool
    apply_gprs: bool
    tid: int
    def __init__(self, regs: _Optional[_Union[Registers, _Mapping]] = ..., apply_rip: _Optional[bool] = ..., apply_rflags: _Optional[bool] = ..., apply_dr: _Optional[bool] = ..., apply_gprs: _Optional[bool] = ..., tid: _Optional[int] = ...) -> None: ...

class SetRegsResponse(_message.Message):
    __slots__ = ("status", "warnings")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class ThreadInfo(_message.Message):
    __slots__ = ("tid", "teb", "suspend_count", "start_address")
    TID_FIELD_NUMBER: _ClassVar[int]
    TEB_FIELD_NUMBER: _ClassVar[int]
    SUSPEND_COUNT_FIELD_NUMBER: _ClassVar[int]
    START_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    tid: int
    teb: int
    suspend_count: int
    start_address: int
    def __init__(self, tid: _Optional[int] = ..., teb: _Optional[int] = ..., suspend_count: _Optional[int] = ..., start_address: _Optional[int] = ...) -> None: ...

class GetThreadsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetThreadsResponse(_message.Message):
    __slots__ = ("status", "threads", "current_tid")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    THREADS_FIELD_NUMBER: _ClassVar[int]
    CURRENT_TID_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    threads: _containers.RepeatedCompositeFieldContainer[ThreadInfo]
    current_tid: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., threads: _Optional[_Iterable[_Union[ThreadInfo, _Mapping]]] = ..., current_tid: _Optional[int] = ...) -> None: ...

class StackFrame(_message.Message):
    __slots__ = ("frame", "return_address", "symbol", "displacement", "module")
    FRAME_FIELD_NUMBER: _ClassVar[int]
    RETURN_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    DISPLACEMENT_FIELD_NUMBER: _ClassVar[int]
    MODULE_FIELD_NUMBER: _ClassVar[int]
    frame: int
    return_address: int
    symbol: str
    displacement: int
    module: str
    def __init__(self, frame: _Optional[int] = ..., return_address: _Optional[int] = ..., symbol: _Optional[str] = ..., displacement: _Optional[int] = ..., module: _Optional[str] = ...) -> None: ...

class StacktraceRequest(_message.Message):
    __slots__ = ("max_frames", "tid")
    MAX_FRAMES_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    max_frames: int
    tid: int
    def __init__(self, max_frames: _Optional[int] = ..., tid: _Optional[int] = ...) -> None: ...

class StacktraceResponse(_message.Message):
    __slots__ = ("status", "frames")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    FRAMES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    frames: _containers.RepeatedCompositeFieldContainer[StackFrame]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., frames: _Optional[_Iterable[_Union[StackFrame, _Mapping]]] = ...) -> None: ...

class MemoryRegionsRequest(_message.Message):
    __slots__ = ("pid", "limit", "offset")
    PID_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    pid: int
    limit: int
    offset: int
    def __init__(self, pid: _Optional[int] = ..., limit: _Optional[int] = ..., offset: _Optional[int] = ...) -> None: ...

class MemoryRegion(_message.Message):
    __slots__ = ("base", "size", "state", "protect", "type", "module")
    BASE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    PROTECT_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    MODULE_FIELD_NUMBER: _ClassVar[int]
    base: int
    size: int
    state: int
    protect: int
    type: int
    module: str
    def __init__(self, base: _Optional[int] = ..., size: _Optional[int] = ..., state: _Optional[int] = ..., protect: _Optional[int] = ..., type: _Optional[int] = ..., module: _Optional[str] = ...) -> None: ...

class MemoryRegionsResponse(_message.Message):
    __slots__ = ("status", "regions")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REGIONS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    regions: _containers.RepeatedCompositeFieldContainer[MemoryRegion]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., regions: _Optional[_Iterable[_Union[MemoryRegion, _Mapping]]] = ...) -> None: ...

class DebugEvent(_message.Message):
    __slots__ = ("seq", "kind", "tid", "address", "exception_code", "description", "timestamp_unix", "pid", "bp_id", "first_chance", "module_base")
    class Kind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        BREAKPOINT_SW: _ClassVar[DebugEvent.Kind]
        BREAKPOINT_HW: _ClassVar[DebugEvent.Kind]
        EXCEPTION: _ClassVar[DebugEvent.Kind]
        PROCESS_EXIT: _ClassVar[DebugEvent.Kind]
        THREAD_CREATE: _ClassVar[DebugEvent.Kind]
        THREAD_EXIT: _ClassVar[DebugEvent.Kind]
        MODULE_LOAD: _ClassVar[DebugEvent.Kind]
        SESSION_STATUS: _ClassVar[DebugEvent.Kind]
        MODULE_UNLOAD: _ClassVar[DebugEvent.Kind]
    BREAKPOINT_SW: DebugEvent.Kind
    BREAKPOINT_HW: DebugEvent.Kind
    EXCEPTION: DebugEvent.Kind
    PROCESS_EXIT: DebugEvent.Kind
    THREAD_CREATE: DebugEvent.Kind
    THREAD_EXIT: DebugEvent.Kind
    MODULE_LOAD: DebugEvent.Kind
    SESSION_STATUS: DebugEvent.Kind
    MODULE_UNLOAD: DebugEvent.Kind
    SEQ_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_CODE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_UNIX_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    BP_ID_FIELD_NUMBER: _ClassVar[int]
    FIRST_CHANCE_FIELD_NUMBER: _ClassVar[int]
    MODULE_BASE_FIELD_NUMBER: _ClassVar[int]
    seq: int
    kind: DebugEvent.Kind
    tid: int
    address: int
    exception_code: int
    description: str
    timestamp_unix: int
    pid: int
    bp_id: int
    first_chance: bool
    module_base: int
    def __init__(self, seq: _Optional[int] = ..., kind: _Optional[_Union[DebugEvent.Kind, str]] = ..., tid: _Optional[int] = ..., address: _Optional[int] = ..., exception_code: _Optional[int] = ..., description: _Optional[str] = ..., timestamp_unix: _Optional[int] = ..., pid: _Optional[int] = ..., bp_id: _Optional[int] = ..., first_chance: _Optional[bool] = ..., module_base: _Optional[int] = ...) -> None: ...

class LaunchRequest(_message.Message):
    __slots__ = ("cmdline", "working_dir", "break_on_entry", "addr_width", "monitor")
    CMDLINE_FIELD_NUMBER: _ClassVar[int]
    WORKING_DIR_FIELD_NUMBER: _ClassVar[int]
    BREAK_ON_ENTRY_FIELD_NUMBER: _ClassVar[int]
    ADDR_WIDTH_FIELD_NUMBER: _ClassVar[int]
    MONITOR_FIELD_NUMBER: _ClassVar[int]
    cmdline: str
    working_dir: str
    break_on_entry: bool
    addr_width: int
    monitor: bool
    def __init__(self, cmdline: _Optional[str] = ..., working_dir: _Optional[str] = ..., break_on_entry: _Optional[bool] = ..., addr_width: _Optional[int] = ..., monitor: _Optional[bool] = ...) -> None: ...

class LaunchResponse(_message.Message):
    __slots__ = ("status", "pid", "initial_tid")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    INITIAL_TID_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    pid: int
    initial_tid: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., pid: _Optional[int] = ..., initial_tid: _Optional[int] = ...) -> None: ...

class AttachRequest(_message.Message):
    __slots__ = ("pid", "monitor")
    PID_FIELD_NUMBER: _ClassVar[int]
    MONITOR_FIELD_NUMBER: _ClassVar[int]
    pid: int
    monitor: bool
    def __init__(self, pid: _Optional[int] = ..., monitor: _Optional[bool] = ...) -> None: ...

class DetachRequest(_message.Message):
    __slots__ = ("kill",)
    KILL_FIELD_NUMBER: _ClassVar[int]
    kill: bool
    def __init__(self, kill: _Optional[bool] = ...) -> None: ...

class ContinueRequest(_message.Message):
    __slots__ = ("include_context",)
    INCLUDE_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    include_context: bool
    def __init__(self, include_context: _Optional[bool] = ...) -> None: ...

class DebugReadRequest(_message.Message):
    __slots__ = ("address", "size")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    address: int
    size: int
    def __init__(self, address: _Optional[int] = ..., size: _Optional[int] = ...) -> None: ...

class DebugReadResponse(_message.Message):
    __slots__ = ("status", "data")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    data: bytes
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class DebugWriteRequest(_message.Message):
    __slots__ = ("address", "data")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    address: int
    data: bytes
    def __init__(self, address: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...

class DebugWriteResponse(_message.Message):
    __slots__ = ("status", "state")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    state: StopInfo
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., state: _Optional[_Union[StopInfo, _Mapping]] = ...) -> None: ...

class StreamDebugEventsRequest(_message.Message):
    __slots__ = ("from_seq",)
    FROM_SEQ_FIELD_NUMBER: _ClassVar[int]
    from_seq: int
    def __init__(self, from_seq: _Optional[int] = ...) -> None: ...

class ExecuteCommandRequest(_message.Message):
    __slots__ = ("command",)
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    command: str
    def __init__(self, command: _Optional[str] = ...) -> None: ...

class ExecuteCommandResponse(_message.Message):
    __slots__ = ("status", "output", "state")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    output: str
    state: StopInfo
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., output: _Optional[str] = ..., state: _Optional[_Union[StopInfo, _Mapping]] = ...) -> None: ...

class StopInfo(_message.Message):
    __slots__ = ("active", "stopped", "timed_out", "pid", "tid", "rip", "symbol", "stop_reason", "seq", "arch", "exception_code", "first_chance", "bp_id", "regs", "bytes_at_rip_hex")
    ACTIVE_FIELD_NUMBER: _ClassVar[int]
    STOPPED_FIELD_NUMBER: _ClassVar[int]
    TIMED_OUT_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    RIP_FIELD_NUMBER: _ClassVar[int]
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    STOP_REASON_FIELD_NUMBER: _ClassVar[int]
    SEQ_FIELD_NUMBER: _ClassVar[int]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_CODE_FIELD_NUMBER: _ClassVar[int]
    FIRST_CHANCE_FIELD_NUMBER: _ClassVar[int]
    BP_ID_FIELD_NUMBER: _ClassVar[int]
    REGS_FIELD_NUMBER: _ClassVar[int]
    BYTES_AT_RIP_HEX_FIELD_NUMBER: _ClassVar[int]
    active: bool
    stopped: bool
    timed_out: bool
    pid: int
    tid: int
    rip: int
    symbol: str
    stop_reason: str
    seq: int
    arch: str
    exception_code: int
    first_chance: bool
    bp_id: int
    regs: _containers.RepeatedCompositeFieldContainer[Register]
    bytes_at_rip_hex: str
    def __init__(self, active: _Optional[bool] = ..., stopped: _Optional[bool] = ..., timed_out: _Optional[bool] = ..., pid: _Optional[int] = ..., tid: _Optional[int] = ..., rip: _Optional[int] = ..., symbol: _Optional[str] = ..., stop_reason: _Optional[str] = ..., seq: _Optional[int] = ..., arch: _Optional[str] = ..., exception_code: _Optional[int] = ..., first_chance: _Optional[bool] = ..., bp_id: _Optional[int] = ..., regs: _Optional[_Iterable[_Union[Register, _Mapping]]] = ..., bytes_at_rip_hex: _Optional[str] = ...) -> None: ...

class Register(_message.Message):
    __slots__ = ("name", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: int
    def __init__(self, name: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...

class DebugOpStatus(_message.Message):
    __slots__ = ("status", "state")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    state: StopInfo
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., state: _Optional[_Union[StopInfo, _Mapping]] = ...) -> None: ...

class AttachResponse(_message.Message):
    __slots__ = ("status", "state")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    state: StopInfo
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., state: _Optional[_Union[StopInfo, _Mapping]] = ...) -> None: ...

class DetachResponse(_message.Message):
    __slots__ = ("status", "state")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    state: StopInfo
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., state: _Optional[_Union[StopInfo, _Mapping]] = ...) -> None: ...

class ContinueResponse(_message.Message):
    __slots__ = ("status", "state")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    state: StopInfo
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., state: _Optional[_Union[StopInfo, _Mapping]] = ...) -> None: ...

class DebugStatusRequest(_message.Message):
    __slots__ = ("include_context",)
    INCLUDE_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    include_context: bool
    def __init__(self, include_context: _Optional[bool] = ...) -> None: ...

class DebugStatusResponse(_message.Message):
    __slots__ = ("status", "state")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    state: StopInfo
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., state: _Optional[_Union[StopInfo, _Mapping]] = ...) -> None: ...

class PauseRequest(_message.Message):
    __slots__ = ("timeout_ms", "include_context")
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    timeout_ms: int
    include_context: bool
    def __init__(self, timeout_ms: _Optional[int] = ..., include_context: _Optional[bool] = ...) -> None: ...

class WaitRequest(_message.Message):
    __slots__ = ("timeout_ms", "include_context")
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    timeout_ms: int
    include_context: bool
    def __init__(self, timeout_ms: _Optional[int] = ..., include_context: _Optional[bool] = ...) -> None: ...

class RunRequest(_message.Message):
    __slots__ = ("timeout_ms", "include_context")
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    timeout_ms: int
    include_context: bool
    def __init__(self, timeout_ms: _Optional[int] = ..., include_context: _Optional[bool] = ...) -> None: ...

class RunToRequest(_message.Message):
    __slots__ = ("address", "timeout_ms", "include_context")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    address: int
    timeout_ms: int
    include_context: bool
    def __init__(self, address: _Optional[int] = ..., timeout_ms: _Optional[int] = ..., include_context: _Optional[bool] = ...) -> None: ...

class StepOutRequest(_message.Message):
    __slots__ = ("timeout_ms", "include_context")
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    timeout_ms: int
    include_context: bool
    def __init__(self, timeout_ms: _Optional[int] = ..., include_context: _Optional[bool] = ...) -> None: ...

class CancelRequest(_message.Message):
    __slots__ = ("pid",)
    PID_FIELD_NUMBER: _ClassVar[int]
    pid: int
    def __init__(self, pid: _Optional[int] = ...) -> None: ...

class CancelResponse(_message.Message):
    __slots__ = ("status", "state")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    state: StopInfo
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., state: _Optional[_Union[StopInfo, _Mapping]] = ...) -> None: ...

class DisasmRequest(_message.Message):
    __slots__ = ("address", "count")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    address: int
    count: int
    def __init__(self, address: _Optional[int] = ..., count: _Optional[int] = ...) -> None: ...

class DisasmLine(_message.Message):
    __slots__ = ("address", "bytes_hex", "text")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    BYTES_HEX_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    address: int
    bytes_hex: str
    text: str
    def __init__(self, address: _Optional[int] = ..., bytes_hex: _Optional[str] = ..., text: _Optional[str] = ...) -> None: ...

class DisasmResponse(_message.Message):
    __slots__ = ("status", "lines")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LINES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    lines: _containers.RepeatedCompositeFieldContainer[DisasmLine]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., lines: _Optional[_Iterable[_Union[DisasmLine, _Mapping]]] = ...) -> None: ...

class ResolveRequest(_message.Message):
    __slots__ = ("symbol",)
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    symbol: str
    def __init__(self, symbol: _Optional[str] = ...) -> None: ...

class ResolveResponse(_message.Message):
    __slots__ = ("status", "address", "canonical")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    CANONICAL_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    address: int
    canonical: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., address: _Optional[int] = ..., canonical: _Optional[str] = ...) -> None: ...

class DebugDumpRequest(_message.Message):
    __slots__ = ("path", "kind")
    PATH_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    path: str
    kind: str
    def __init__(self, path: _Optional[str] = ..., kind: _Optional[str] = ...) -> None: ...

class DebugDumpResponse(_message.Message):
    __slots__ = ("status", "path", "bytes")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    path: str
    bytes: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., path: _Optional[str] = ..., bytes: _Optional[int] = ...) -> None: ...

class DebugModuleInfo(_message.Message):
    __slots__ = ("base", "size", "name", "path", "timestamp", "loaded")
    BASE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    LOADED_FIELD_NUMBER: _ClassVar[int]
    base: int
    size: int
    name: str
    path: str
    timestamp: int
    loaded: bool
    def __init__(self, base: _Optional[int] = ..., size: _Optional[int] = ..., name: _Optional[str] = ..., path: _Optional[str] = ..., timestamp: _Optional[int] = ..., loaded: _Optional[bool] = ...) -> None: ...

class DebugModulesRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DebugModulesResponse(_message.Message):
    __slots__ = ("status", "modules")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MODULES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    modules: _containers.RepeatedCompositeFieldContainer[DebugModuleInfo]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., modules: _Optional[_Iterable[_Union[DebugModuleInfo, _Mapping]]] = ...) -> None: ...

class ExceptionFilterRequest(_message.Message):
    __slots__ = ("code", "action")
    CODE_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    code: int
    action: str
    def __init__(self, code: _Optional[int] = ..., action: _Optional[str] = ...) -> None: ...

class ExceptionFilterResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ...) -> None: ...

class BpAddRequest(_message.Message):
    __slots__ = ("kind", "address", "slot", "size", "access", "kernel_target", "tid", "pid", "dangerous_ok", "via_debugger", "condition", "commands", "pass_count", "one_shot", "match_tid")
    class Kind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        SW: _ClassVar[BpAddRequest.Kind]
        HW: _ClassVar[BpAddRequest.Kind]
    SW: BpAddRequest.Kind
    HW: BpAddRequest.Kind
    KIND_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SLOT_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    KERNEL_TARGET_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    GLOBAL_FIELD_NUMBER: _ClassVar[int]
    DANGEROUS_OK_FIELD_NUMBER: _ClassVar[int]
    VIA_DEBUGGER_FIELD_NUMBER: _ClassVar[int]
    CONDITION_FIELD_NUMBER: _ClassVar[int]
    COMMANDS_FIELD_NUMBER: _ClassVar[int]
    PASS_COUNT_FIELD_NUMBER: _ClassVar[int]
    ONE_SHOT_FIELD_NUMBER: _ClassVar[int]
    MATCH_TID_FIELD_NUMBER: _ClassVar[int]
    kind: BpAddRequest.Kind
    address: int
    slot: int
    size: int
    access: str
    kernel_target: bool
    tid: int
    pid: int
    dangerous_ok: bool
    via_debugger: bool
    condition: str
    commands: str
    pass_count: int
    one_shot: bool
    match_tid: int
    def __init__(self, kind: _Optional[_Union[BpAddRequest.Kind, str]] = ..., address: _Optional[int] = ..., slot: _Optional[int] = ..., size: _Optional[int] = ..., access: _Optional[str] = ..., kernel_target: _Optional[bool] = ..., tid: _Optional[int] = ..., pid: _Optional[int] = ..., dangerous_ok: _Optional[bool] = ..., via_debugger: _Optional[bool] = ..., condition: _Optional[str] = ..., commands: _Optional[str] = ..., pass_count: _Optional[int] = ..., one_shot: _Optional[bool] = ..., match_tid: _Optional[int] = ..., **kwargs) -> None: ...

class BpAddResponse(_message.Message):
    __slots__ = ("status", "bp_id")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    BP_ID_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    bp_id: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., bp_id: _Optional[int] = ...) -> None: ...

class BpRemoveRequest(_message.Message):
    __slots__ = ("bp_id",)
    BP_ID_FIELD_NUMBER: _ClassVar[int]
    bp_id: int
    def __init__(self, bp_id: _Optional[int] = ...) -> None: ...

class BpListRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class BpEntry(_message.Message):
    __slots__ = ("bp_id", "kind", "address", "slot", "access", "enabled", "description", "pid", "tid", "size")
    BP_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SLOT_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    bp_id: int
    kind: str
    address: int
    slot: int
    access: str
    enabled: bool
    description: str
    pid: int
    tid: int
    size: int
    def __init__(self, bp_id: _Optional[int] = ..., kind: _Optional[str] = ..., address: _Optional[int] = ..., slot: _Optional[int] = ..., access: _Optional[str] = ..., enabled: _Optional[bool] = ..., description: _Optional[str] = ..., pid: _Optional[int] = ..., tid: _Optional[int] = ..., size: _Optional[int] = ...) -> None: ...

class BpListResponse(_message.Message):
    __slots__ = ("status", "breakpoints")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    BREAKPOINTS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    breakpoints: _containers.RepeatedCompositeFieldContainer[BpEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., breakpoints: _Optional[_Iterable[_Union[BpEntry, _Mapping]]] = ...) -> None: ...

class BpSetEnabledRequest(_message.Message):
    __slots__ = ("bp_id", "enabled")
    BP_ID_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    bp_id: int
    enabled: bool
    def __init__(self, bp_id: _Optional[int] = ..., enabled: _Optional[bool] = ...) -> None: ...

class UploadHeader(_message.Message):
    __slots__ = ("path", "size")
    PATH_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    path: str
    size: int
    def __init__(self, path: _Optional[str] = ..., size: _Optional[int] = ...) -> None: ...

class UploadChunk(_message.Message):
    __slots__ = ("header", "data")
    HEADER_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    header: UploadHeader
    data: bytes
    def __init__(self, header: _Optional[_Union[UploadHeader, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class UploadResponse(_message.Message):
    __slots__ = ("status", "path", "sha256", "bytes_written")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    BYTES_WRITTEN_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    path: str
    sha256: str
    bytes_written: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., path: _Optional[str] = ..., sha256: _Optional[str] = ..., bytes_written: _Optional[int] = ...) -> None: ...

class DumpedSection(_message.Message):
    __slots__ = ("name", "va", "size", "dumped_bytes", "complete")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VA_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    DUMPED_BYTES_FIELD_NUMBER: _ClassVar[int]
    COMPLETE_FIELD_NUMBER: _ClassVar[int]
    name: str
    va: int
    size: int
    dumped_bytes: int
    complete: bool
    def __init__(self, name: _Optional[str] = ..., va: _Optional[int] = ..., size: _Optional[int] = ..., dumped_bytes: _Optional[int] = ..., complete: _Optional[bool] = ...) -> None: ...

class DownloadHeader(_message.Message):
    __slots__ = ("size", "sha256", "notes", "sections", "via_snapshot")
    SIZE_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    NOTES_FIELD_NUMBER: _ClassVar[int]
    SECTIONS_FIELD_NUMBER: _ClassVar[int]
    VIA_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    size: int
    sha256: str
    notes: str
    sections: _containers.RepeatedCompositeFieldContainer[DumpedSection]
    via_snapshot: bool
    def __init__(self, size: _Optional[int] = ..., sha256: _Optional[str] = ..., notes: _Optional[str] = ..., sections: _Optional[_Iterable[_Union[DumpedSection, _Mapping]]] = ..., via_snapshot: _Optional[bool] = ...) -> None: ...

class DownloadChunk(_message.Message):
    __slots__ = ("header", "data")
    HEADER_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    header: DownloadHeader
    data: bytes
    def __init__(self, header: _Optional[_Union[DownloadHeader, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class DownloadRequest(_message.Message):
    __slots__ = ("path", "offset", "length")
    PATH_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    path: str
    offset: int
    length: int
    def __init__(self, path: _Optional[str] = ..., offset: _Optional[int] = ..., length: _Optional[int] = ...) -> None: ...

class DumpModuleRequest(_message.Message):
    __slots__ = ("pid", "module", "quiesce", "dump_type", "kernel")
    PID_FIELD_NUMBER: _ClassVar[int]
    MODULE_FIELD_NUMBER: _ClassVar[int]
    QUIESCE_FIELD_NUMBER: _ClassVar[int]
    DUMP_TYPE_FIELD_NUMBER: _ClassVar[int]
    KERNEL_FIELD_NUMBER: _ClassVar[int]
    pid: int
    module: str
    quiesce: bool
    dump_type: str
    kernel: bool
    def __init__(self, pid: _Optional[int] = ..., module: _Optional[str] = ..., quiesce: _Optional[bool] = ..., dump_type: _Optional[str] = ..., kernel: _Optional[bool] = ...) -> None: ...

class HashRequest(_message.Message):
    __slots__ = ("path",)
    PATH_FIELD_NUMBER: _ClassVar[int]
    path: str
    def __init__(self, path: _Optional[str] = ...) -> None: ...

class HashResponse(_message.Message):
    __slots__ = ("status", "sha256", "size", "via_snapshot")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    VIA_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    sha256: str
    size: int
    via_snapshot: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., sha256: _Optional[str] = ..., size: _Optional[int] = ..., via_snapshot: _Optional[bool] = ...) -> None: ...

class ListDirRequest(_message.Message):
    __slots__ = ("path", "recursive", "max_entries")
    PATH_FIELD_NUMBER: _ClassVar[int]
    RECURSIVE_FIELD_NUMBER: _ClassVar[int]
    MAX_ENTRIES_FIELD_NUMBER: _ClassVar[int]
    path: str
    recursive: bool
    max_entries: int
    def __init__(self, path: _Optional[str] = ..., recursive: _Optional[bool] = ..., max_entries: _Optional[int] = ...) -> None: ...

class DirEntry(_message.Message):
    __slots__ = ("name", "dir", "size", "mtime_unix")
    NAME_FIELD_NUMBER: _ClassVar[int]
    DIR_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    MTIME_UNIX_FIELD_NUMBER: _ClassVar[int]
    name: str
    dir: bool
    size: int
    mtime_unix: int
    def __init__(self, name: _Optional[str] = ..., dir: _Optional[bool] = ..., size: _Optional[int] = ..., mtime_unix: _Optional[int] = ...) -> None: ...

class ListDirResponse(_message.Message):
    __slots__ = ("status", "entries")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    entries: _containers.RepeatedCompositeFieldContainer[DirEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., entries: _Optional[_Iterable[_Union[DirEntry, _Mapping]]] = ...) -> None: ...

class DeleteRequest(_message.Message):
    __slots__ = ("path", "no_trash")
    PATH_FIELD_NUMBER: _ClassVar[int]
    NO_TRASH_FIELD_NUMBER: _ClassVar[int]
    path: str
    no_trash: bool
    def __init__(self, path: _Optional[str] = ..., no_trash: _Optional[bool] = ...) -> None: ...

class LogTailRequest(_message.Message):
    __slots__ = ("path", "bytes", "from_end", "line_align", "include_rotated")
    PATH_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    FROM_END_FIELD_NUMBER: _ClassVar[int]
    LINE_ALIGN_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_ROTATED_FIELD_NUMBER: _ClassVar[int]
    path: str
    bytes: int
    from_end: bool
    line_align: bool
    include_rotated: bool
    def __init__(self, path: _Optional[str] = ..., bytes: _Optional[int] = ..., from_end: _Optional[bool] = ..., line_align: _Optional[bool] = ..., include_rotated: _Optional[bool] = ...) -> None: ...

class LogTailResponse(_message.Message):
    __slots__ = ("status", "data", "total_size", "tail_offset", "truncated", "rotated_size", "via_snapshot")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    TOTAL_SIZE_FIELD_NUMBER: _ClassVar[int]
    TAIL_OFFSET_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    ROTATED_SIZE_FIELD_NUMBER: _ClassVar[int]
    VIA_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    data: bytes
    total_size: int
    tail_offset: int
    truncated: bool
    rotated_size: int
    via_snapshot: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., data: _Optional[bytes] = ..., total_size: _Optional[int] = ..., tail_offset: _Optional[int] = ..., truncated: _Optional[bool] = ..., rotated_size: _Optional[int] = ..., via_snapshot: _Optional[bool] = ...) -> None: ...

class LogFollowRequest(_message.Message):
    __slots__ = ("path", "from_offset", "initial_tail_bytes", "poll_interval_ms", "max_chunk_bytes", "line_align", "follow_rotation", "duration_s", "max_bytes")
    PATH_FIELD_NUMBER: _ClassVar[int]
    FROM_OFFSET_FIELD_NUMBER: _ClassVar[int]
    INITIAL_TAIL_BYTES_FIELD_NUMBER: _ClassVar[int]
    POLL_INTERVAL_MS_FIELD_NUMBER: _ClassVar[int]
    MAX_CHUNK_BYTES_FIELD_NUMBER: _ClassVar[int]
    LINE_ALIGN_FIELD_NUMBER: _ClassVar[int]
    FOLLOW_ROTATION_FIELD_NUMBER: _ClassVar[int]
    DURATION_S_FIELD_NUMBER: _ClassVar[int]
    MAX_BYTES_FIELD_NUMBER: _ClassVar[int]
    path: str
    from_offset: int
    initial_tail_bytes: int
    poll_interval_ms: int
    max_chunk_bytes: int
    line_align: bool
    follow_rotation: bool
    duration_s: int
    max_bytes: int
    def __init__(self, path: _Optional[str] = ..., from_offset: _Optional[int] = ..., initial_tail_bytes: _Optional[int] = ..., poll_interval_ms: _Optional[int] = ..., max_chunk_bytes: _Optional[int] = ..., line_align: _Optional[bool] = ..., follow_rotation: _Optional[bool] = ..., duration_s: _Optional[int] = ..., max_bytes: _Optional[int] = ...) -> None: ...

class LogFollowChunk(_message.Message):
    __slots__ = ("status", "offset", "data", "rotated", "new_total_size", "eof", "reason", "stat_only")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    ROTATED_FIELD_NUMBER: _ClassVar[int]
    NEW_TOTAL_SIZE_FIELD_NUMBER: _ClassVar[int]
    EOF_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    STAT_ONLY_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    offset: int
    data: bytes
    rotated: bool
    new_total_size: int
    eof: bool
    reason: str
    stat_only: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., offset: _Optional[int] = ..., data: _Optional[bytes] = ..., rotated: _Optional[bool] = ..., new_total_size: _Optional[int] = ..., eof: _Optional[bool] = ..., reason: _Optional[str] = ..., stat_only: _Optional[bool] = ...) -> None: ...

class RunExeRequest(_message.Message):
    __slots__ = ("exe", "args", "working_dir", "timeout_ms", "hidden_window")
    EXE_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    WORKING_DIR_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    HIDDEN_WINDOW_FIELD_NUMBER: _ClassVar[int]
    exe: str
    args: _containers.RepeatedScalarFieldContainer[str]
    working_dir: str
    timeout_ms: int
    hidden_window: bool
    def __init__(self, exe: _Optional[str] = ..., args: _Optional[_Iterable[str]] = ..., working_dir: _Optional[str] = ..., timeout_ms: _Optional[int] = ..., hidden_window: _Optional[bool] = ...) -> None: ...

class RunExeResponse(_message.Message):
    __slots__ = ("status", "exit_code", "stdout_data", "stderr_data", "timed_out", "killed")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    STDOUT_DATA_FIELD_NUMBER: _ClassVar[int]
    STDERR_DATA_FIELD_NUMBER: _ClassVar[int]
    TIMED_OUT_FIELD_NUMBER: _ClassVar[int]
    KILLED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    exit_code: int
    stdout_data: bytes
    stderr_data: bytes
    timed_out: int
    killed: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., exit_code: _Optional[int] = ..., stdout_data: _Optional[bytes] = ..., stderr_data: _Optional[bytes] = ..., timed_out: _Optional[int] = ..., killed: _Optional[bool] = ...) -> None: ...

class RunShellRequest(_message.Message):
    __slots__ = ("shell", "command", "working_dir", "timeout_ms", "encoded_command")
    SHELL_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    WORKING_DIR_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    ENCODED_COMMAND_FIELD_NUMBER: _ClassVar[int]
    shell: ShellKind
    command: str
    working_dir: str
    timeout_ms: int
    encoded_command: str
    def __init__(self, shell: _Optional[_Union[ShellKind, str]] = ..., command: _Optional[str] = ..., working_dir: _Optional[str] = ..., timeout_ms: _Optional[int] = ..., encoded_command: _Optional[str] = ...) -> None: ...

class RunShellResponse(_message.Message):
    __slots__ = ("status", "exit_code", "output")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    exit_code: int
    output: bytes
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., exit_code: _Optional[int] = ..., output: _Optional[bytes] = ...) -> None: ...

class StartShellRequest(_message.Message):
    __slots__ = ("shell", "working_dir")
    SHELL_FIELD_NUMBER: _ClassVar[int]
    WORKING_DIR_FIELD_NUMBER: _ClassVar[int]
    shell: ShellKind
    working_dir: str
    def __init__(self, shell: _Optional[_Union[ShellKind, str]] = ..., working_dir: _Optional[str] = ...) -> None: ...

class StartShellResponse(_message.Message):
    __slots__ = ("status", "session_id")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    session_id: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., session_id: _Optional[int] = ...) -> None: ...

class WriteConsoleRequest(_message.Message):
    __slots__ = ("session_id", "input")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    INPUT_FIELD_NUMBER: _ClassVar[int]
    session_id: int
    input: bytes
    def __init__(self, session_id: _Optional[int] = ..., input: _Optional[bytes] = ...) -> None: ...

class ReadConsoleRequest(_message.Message):
    __slots__ = ("session_id", "max_bytes", "timeout_ms")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    MAX_BYTES_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    session_id: int
    max_bytes: int
    timeout_ms: int
    def __init__(self, session_id: _Optional[int] = ..., max_bytes: _Optional[int] = ..., timeout_ms: _Optional[int] = ...) -> None: ...

class ConsoleData(_message.Message):
    __slots__ = ("status", "data", "eof", "session_id")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    EOF_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    data: bytes
    eof: bool
    session_id: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., data: _Optional[bytes] = ..., eof: _Optional[bool] = ..., session_id: _Optional[int] = ...) -> None: ...

class ShellSessionRequest(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: int
    def __init__(self, session_id: _Optional[int] = ...) -> None: ...

class StreamConsoleRequest(_message.Message):
    __slots__ = ("session_id",)
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: int
    def __init__(self, session_id: _Optional[int] = ...) -> None: ...

class KillProcessRequest(_message.Message):
    __slots__ = ("pid",)
    PID_FIELD_NUMBER: _ClassVar[int]
    pid: int
    def __init__(self, pid: _Optional[int] = ...) -> None: ...

class PidRequest(_message.Message):
    __slots__ = ("pid",)
    PID_FIELD_NUMBER: _ClassVar[int]
    pid: int
    def __init__(self, pid: _Optional[int] = ...) -> None: ...

class RunDetachedRequest(_message.Message):
    __slots__ = ("cmdline", "working_dir", "stdout_path", "stderr_path", "hidden_window", "env")
    class EnvEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    CMDLINE_FIELD_NUMBER: _ClassVar[int]
    WORKING_DIR_FIELD_NUMBER: _ClassVar[int]
    STDOUT_PATH_FIELD_NUMBER: _ClassVar[int]
    STDERR_PATH_FIELD_NUMBER: _ClassVar[int]
    HIDDEN_WINDOW_FIELD_NUMBER: _ClassVar[int]
    ENV_FIELD_NUMBER: _ClassVar[int]
    cmdline: str
    working_dir: str
    stdout_path: str
    stderr_path: str
    hidden_window: bool
    env: _containers.ScalarMap[str, str]
    def __init__(self, cmdline: _Optional[str] = ..., working_dir: _Optional[str] = ..., stdout_path: _Optional[str] = ..., stderr_path: _Optional[str] = ..., hidden_window: _Optional[bool] = ..., env: _Optional[_Mapping[str, str]] = ...) -> None: ...

class RunDetachedResponse(_message.Message):
    __slots__ = ("status", "handle_id", "pid", "stdout_path", "stderr_path", "started_ts")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HANDLE_ID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    STDOUT_PATH_FIELD_NUMBER: _ClassVar[int]
    STDERR_PATH_FIELD_NUMBER: _ClassVar[int]
    STARTED_TS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    handle_id: str
    pid: int
    stdout_path: str
    stderr_path: str
    started_ts: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., handle_id: _Optional[str] = ..., pid: _Optional[int] = ..., stdout_path: _Optional[str] = ..., stderr_path: _Optional[str] = ..., started_ts: _Optional[int] = ...) -> None: ...

class DetachedHandleRequest(_message.Message):
    __slots__ = ("handle_id",)
    HANDLE_ID_FIELD_NUMBER: _ClassVar[int]
    handle_id: str
    def __init__(self, handle_id: _Optional[str] = ...) -> None: ...

class DetachedStatusResponse(_message.Message):
    __slots__ = ("status", "running", "exit_code", "stdout_size", "stderr_size", "exited_ts", "stdout_path", "stderr_path", "pid")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RUNNING_FIELD_NUMBER: _ClassVar[int]
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    STDOUT_SIZE_FIELD_NUMBER: _ClassVar[int]
    STDERR_SIZE_FIELD_NUMBER: _ClassVar[int]
    EXITED_TS_FIELD_NUMBER: _ClassVar[int]
    STDOUT_PATH_FIELD_NUMBER: _ClassVar[int]
    STDERR_PATH_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    running: bool
    exit_code: int
    stdout_size: int
    stderr_size: int
    exited_ts: int
    stdout_path: str
    stderr_path: str
    pid: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., running: _Optional[bool] = ..., exit_code: _Optional[int] = ..., stdout_size: _Optional[int] = ..., stderr_size: _Optional[int] = ..., exited_ts: _Optional[int] = ..., stdout_path: _Optional[str] = ..., stderr_path: _Optional[str] = ..., pid: _Optional[int] = ...) -> None: ...

class DetachedTailRequest(_message.Message):
    __slots__ = ("handle_id", "bytes", "stderr_too")
    HANDLE_ID_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    STDERR_TOO_FIELD_NUMBER: _ClassVar[int]
    handle_id: str
    bytes: int
    stderr_too: bool
    def __init__(self, handle_id: _Optional[str] = ..., bytes: _Optional[int] = ..., stderr_too: _Optional[bool] = ...) -> None: ...

class DetachedTailResponse(_message.Message):
    __slots__ = ("status", "stdout_tail", "stderr_tail", "stdout_total", "stderr_total")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STDOUT_TAIL_FIELD_NUMBER: _ClassVar[int]
    STDERR_TAIL_FIELD_NUMBER: _ClassVar[int]
    STDOUT_TOTAL_FIELD_NUMBER: _ClassVar[int]
    STDERR_TOTAL_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    stdout_tail: bytes
    stderr_tail: bytes
    stdout_total: int
    stderr_total: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., stdout_tail: _Optional[bytes] = ..., stderr_tail: _Optional[bytes] = ..., stdout_total: _Optional[int] = ..., stderr_total: _Optional[int] = ...) -> None: ...

class ListShellsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListShellsResponse(_message.Message):
    __slots__ = ("status", "session_ids")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SESSION_IDS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    session_ids: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., session_ids: _Optional[_Iterable[int]] = ...) -> None: ...

class CallFunctionRequest(_message.Message):
    __slots__ = ("pid", "target_va", "args", "space", "timeout_ms", "flags")
    PID_FIELD_NUMBER: _ClassVar[int]
    TARGET_VA_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    pid: int
    target_va: int
    args: _containers.RepeatedScalarFieldContainer[int]
    space: CallSpace
    timeout_ms: int
    flags: int
    def __init__(self, pid: _Optional[int] = ..., target_va: _Optional[int] = ..., args: _Optional[_Iterable[int]] = ..., space: _Optional[_Union[CallSpace, str]] = ..., timeout_ms: _Optional[int] = ..., flags: _Optional[int] = ...) -> None: ...

class CallFunctionResponse(_message.Message):
    __slots__ = ("status", "return_value", "last_error", "exit_code", "timed_out", "exception", "exception_code", "thread_tid", "stub_va")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RETURN_VALUE_FIELD_NUMBER: _ClassVar[int]
    LAST_ERROR_FIELD_NUMBER: _ClassVar[int]
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    TIMED_OUT_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_CODE_FIELD_NUMBER: _ClassVar[int]
    THREAD_TID_FIELD_NUMBER: _ClassVar[int]
    STUB_VA_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    return_value: int
    last_error: int
    exit_code: int
    timed_out: bool
    exception: bool
    exception_code: int
    thread_tid: int
    stub_va: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., return_value: _Optional[int] = ..., last_error: _Optional[int] = ..., exit_code: _Optional[int] = ..., timed_out: _Optional[bool] = ..., exception: _Optional[bool] = ..., exception_code: _Optional[int] = ..., thread_tid: _Optional[int] = ..., stub_va: _Optional[int] = ...) -> None: ...

class RegGetRequest(_message.Message):
    __slots__ = ("hive", "subkey", "value", "wow64_32", "impersonate")
    HIVE_FIELD_NUMBER: _ClassVar[int]
    SUBKEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    WOW64_32_FIELD_NUMBER: _ClassVar[int]
    IMPERSONATE_FIELD_NUMBER: _ClassVar[int]
    hive: str
    subkey: str
    value: str
    wow64_32: bool
    impersonate: str
    def __init__(self, hive: _Optional[str] = ..., subkey: _Optional[str] = ..., value: _Optional[str] = ..., wow64_32: _Optional[bool] = ..., impersonate: _Optional[str] = ...) -> None: ...

class RegGetResponse(_message.Message):
    __slots__ = ("status", "type", "data", "data_str", "data_qword", "data_multi_sz")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    DATA_STR_FIELD_NUMBER: _ClassVar[int]
    DATA_QWORD_FIELD_NUMBER: _ClassVar[int]
    DATA_MULTI_SZ_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    type: int
    data: bytes
    data_str: str
    data_qword: int
    data_multi_sz: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., type: _Optional[int] = ..., data: _Optional[bytes] = ..., data_str: _Optional[str] = ..., data_qword: _Optional[int] = ..., data_multi_sz: _Optional[_Iterable[str]] = ...) -> None: ...

class RegSetRequest(_message.Message):
    __slots__ = ("hive", "subkey", "value", "type", "data", "wow64_32", "create_subkey", "impersonate")
    HIVE_FIELD_NUMBER: _ClassVar[int]
    SUBKEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    WOW64_32_FIELD_NUMBER: _ClassVar[int]
    CREATE_SUBKEY_FIELD_NUMBER: _ClassVar[int]
    IMPERSONATE_FIELD_NUMBER: _ClassVar[int]
    hive: str
    subkey: str
    value: str
    type: int
    data: bytes
    wow64_32: bool
    create_subkey: bool
    impersonate: str
    def __init__(self, hive: _Optional[str] = ..., subkey: _Optional[str] = ..., value: _Optional[str] = ..., type: _Optional[int] = ..., data: _Optional[bytes] = ..., wow64_32: _Optional[bool] = ..., create_subkey: _Optional[bool] = ..., impersonate: _Optional[str] = ...) -> None: ...

class RegSetResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ...) -> None: ...

class RegEnumRequest(_message.Message):
    __slots__ = ("hive", "subkey", "wow64_32", "want_subkeys", "want_values", "impersonate")
    HIVE_FIELD_NUMBER: _ClassVar[int]
    SUBKEY_FIELD_NUMBER: _ClassVar[int]
    WOW64_32_FIELD_NUMBER: _ClassVar[int]
    WANT_SUBKEYS_FIELD_NUMBER: _ClassVar[int]
    WANT_VALUES_FIELD_NUMBER: _ClassVar[int]
    IMPERSONATE_FIELD_NUMBER: _ClassVar[int]
    hive: str
    subkey: str
    wow64_32: bool
    want_subkeys: bool
    want_values: bool
    impersonate: str
    def __init__(self, hive: _Optional[str] = ..., subkey: _Optional[str] = ..., wow64_32: _Optional[bool] = ..., want_subkeys: _Optional[bool] = ..., want_values: _Optional[bool] = ..., impersonate: _Optional[str] = ...) -> None: ...

class RegValueMeta(_message.Message):
    __slots__ = ("name", "type", "size")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    name: str
    type: int
    size: int
    def __init__(self, name: _Optional[str] = ..., type: _Optional[int] = ..., size: _Optional[int] = ...) -> None: ...

class RegEnumResponse(_message.Message):
    __slots__ = ("status", "subkeys", "values")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SUBKEYS_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    subkeys: _containers.RepeatedScalarFieldContainer[str]
    values: _containers.RepeatedCompositeFieldContainer[RegValueMeta]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., subkeys: _Optional[_Iterable[str]] = ..., values: _Optional[_Iterable[_Union[RegValueMeta, _Mapping]]] = ...) -> None: ...

class RegDeleteRequest(_message.Message):
    __slots__ = ("hive", "subkey", "value", "recursive", "wow64_32", "impersonate")
    HIVE_FIELD_NUMBER: _ClassVar[int]
    SUBKEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    RECURSIVE_FIELD_NUMBER: _ClassVar[int]
    WOW64_32_FIELD_NUMBER: _ClassVar[int]
    IMPERSONATE_FIELD_NUMBER: _ClassVar[int]
    hive: str
    subkey: str
    value: str
    recursive: bool
    wow64_32: bool
    impersonate: str
    def __init__(self, hive: _Optional[str] = ..., subkey: _Optional[str] = ..., value: _Optional[str] = ..., recursive: _Optional[bool] = ..., wow64_32: _Optional[bool] = ..., impersonate: _Optional[str] = ...) -> None: ...

class RegDeleteResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ...) -> None: ...

class WdgArmRequest(_message.Message):
    __slots__ = ("id", "deadline_ms", "bugcheck_code", "flags", "cookie", "label")
    ID_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_MS_FIELD_NUMBER: _ClassVar[int]
    BUGCHECK_CODE_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    COOKIE_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    id: int
    deadline_ms: int
    bugcheck_code: int
    flags: int
    cookie: int
    label: str
    def __init__(self, id: _Optional[int] = ..., deadline_ms: _Optional[int] = ..., bugcheck_code: _Optional[int] = ..., flags: _Optional[int] = ..., cookie: _Optional[int] = ..., label: _Optional[str] = ...) -> None: ...

class WdgArmResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ...) -> None: ...

class WdgKickRequest(_message.Message):
    __slots__ = ("id", "deadline_ms", "cookie")
    ID_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_MS_FIELD_NUMBER: _ClassVar[int]
    COOKIE_FIELD_NUMBER: _ClassVar[int]
    id: int
    deadline_ms: int
    cookie: int
    def __init__(self, id: _Optional[int] = ..., deadline_ms: _Optional[int] = ..., cookie: _Optional[int] = ...) -> None: ...

class WdgKickResponse(_message.Message):
    __slots__ = ("status", "kick_count", "last_kick_us", "deadline_us")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    KICK_COUNT_FIELD_NUMBER: _ClassVar[int]
    LAST_KICK_US_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_US_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    kick_count: int
    last_kick_us: int
    deadline_us: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., kick_count: _Optional[int] = ..., last_kick_us: _Optional[int] = ..., deadline_us: _Optional[int] = ...) -> None: ...

class WdgDisarmRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class WdgListRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class WdgEntry(_message.Message):
    __slots__ = ("id", "bugcheck_code", "deadline_us", "last_kick_us", "kick_count", "cookie", "armed_us", "label", "remaining_ms")
    ID_FIELD_NUMBER: _ClassVar[int]
    BUGCHECK_CODE_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_US_FIELD_NUMBER: _ClassVar[int]
    LAST_KICK_US_FIELD_NUMBER: _ClassVar[int]
    KICK_COUNT_FIELD_NUMBER: _ClassVar[int]
    COOKIE_FIELD_NUMBER: _ClassVar[int]
    ARMED_US_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    REMAINING_MS_FIELD_NUMBER: _ClassVar[int]
    id: int
    bugcheck_code: int
    deadline_us: int
    last_kick_us: int
    kick_count: int
    cookie: int
    armed_us: int
    label: str
    remaining_ms: int
    def __init__(self, id: _Optional[int] = ..., bugcheck_code: _Optional[int] = ..., deadline_us: _Optional[int] = ..., last_kick_us: _Optional[int] = ..., kick_count: _Optional[int] = ..., cookie: _Optional[int] = ..., armed_us: _Optional[int] = ..., label: _Optional[str] = ..., remaining_ms: _Optional[int] = ...) -> None: ...

class WdgListResponse(_message.Message):
    __slots__ = ("status", "entries", "now_us")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    NOW_US_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    entries: _containers.RepeatedCompositeFieldContainer[WdgEntry]
    now_us: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., entries: _Optional[_Iterable[_Union[WdgEntry, _Mapping]]] = ..., now_us: _Optional[int] = ...) -> None: ...

class DeviceIoctlRequest(_message.Message):
    __slots__ = ("device", "code", "in_buffer", "out_size", "timeout_ms")
    DEVICE_FIELD_NUMBER: _ClassVar[int]
    CODE_FIELD_NUMBER: _ClassVar[int]
    IN_BUFFER_FIELD_NUMBER: _ClassVar[int]
    OUT_SIZE_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    device: str
    code: int
    in_buffer: bytes
    out_size: int
    timeout_ms: int
    def __init__(self, device: _Optional[str] = ..., code: _Optional[int] = ..., in_buffer: _Optional[bytes] = ..., out_size: _Optional[int] = ..., timeout_ms: _Optional[int] = ...) -> None: ...

class DeviceIoctlResponse(_message.Message):
    __slots__ = ("status", "out_buffer", "bytes_returned", "last_error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    OUT_BUFFER_FIELD_NUMBER: _ClassVar[int]
    BYTES_RETURNED_FIELD_NUMBER: _ClassVar[int]
    LAST_ERROR_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    out_buffer: bytes
    bytes_returned: int
    last_error: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., out_buffer: _Optional[bytes] = ..., bytes_returned: _Optional[int] = ..., last_error: _Optional[int] = ...) -> None: ...

class EtwProvidersRequest(_message.Message):
    __slots__ = ("name_filter",)
    NAME_FILTER_FIELD_NUMBER: _ClassVar[int]
    name_filter: str
    def __init__(self, name_filter: _Optional[str] = ...) -> None: ...

class EtwProviderInfo(_message.Message):
    __slots__ = ("guid", "name")
    GUID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    guid: str
    name: str
    def __init__(self, guid: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class EtwProvidersResponse(_message.Message):
    __slots__ = ("status", "providers", "count", "truncated")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    providers: _containers.RepeatedCompositeFieldContainer[EtwProviderInfo]
    count: int
    truncated: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., providers: _Optional[_Iterable[_Union[EtwProviderInfo, _Mapping]]] = ..., count: _Optional[int] = ..., truncated: _Optional[bool] = ...) -> None: ...

class EtwSessionsRequest(_message.Message):
    __slots__ = ("name_filter",)
    NAME_FILTER_FIELD_NUMBER: _ClassVar[int]
    name_filter: str
    def __init__(self, name_filter: _Optional[str] = ...) -> None: ...

class EtwSessionInfo(_message.Message):
    __slots__ = ("name", "logger_id", "buffers_written", "buffers_lost", "events_lost", "loggers")
    NAME_FIELD_NUMBER: _ClassVar[int]
    LOGGER_ID_FIELD_NUMBER: _ClassVar[int]
    BUFFERS_WRITTEN_FIELD_NUMBER: _ClassVar[int]
    BUFFERS_LOST_FIELD_NUMBER: _ClassVar[int]
    EVENTS_LOST_FIELD_NUMBER: _ClassVar[int]
    LOGGERS_FIELD_NUMBER: _ClassVar[int]
    name: str
    logger_id: int
    buffers_written: int
    buffers_lost: int
    events_lost: int
    loggers: int
    def __init__(self, name: _Optional[str] = ..., logger_id: _Optional[int] = ..., buffers_written: _Optional[int] = ..., buffers_lost: _Optional[int] = ..., events_lost: _Optional[int] = ..., loggers: _Optional[int] = ...) -> None: ...

class EtwSessionsResponse(_message.Message):
    __slots__ = ("status", "sessions", "count")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SESSIONS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    sessions: _containers.RepeatedCompositeFieldContainer[EtwSessionInfo]
    count: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., sessions: _Optional[_Iterable[_Union[EtwSessionInfo, _Mapping]]] = ..., count: _Optional[int] = ...) -> None: ...

class ThreadListRequest(_message.Message):
    __slots__ = ("pid", "kernel", "with_context")
    PID_FIELD_NUMBER: _ClassVar[int]
    KERNEL_FIELD_NUMBER: _ClassVar[int]
    WITH_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    pid: int
    kernel: bool
    with_context: bool
    def __init__(self, pid: _Optional[int] = ..., kernel: _Optional[bool] = ..., with_context: _Optional[bool] = ...) -> None: ...

class SysThreadInfo(_message.Message):
    __slots__ = ("tid", "pid", "start_va", "state", "wait_reason", "base_priority", "win32_start_va", "teb", "context_regs")
    class ContextRegsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    TID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    START_VA_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    WAIT_REASON_FIELD_NUMBER: _ClassVar[int]
    BASE_PRIORITY_FIELD_NUMBER: _ClassVar[int]
    WIN32_START_VA_FIELD_NUMBER: _ClassVar[int]
    TEB_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_REGS_FIELD_NUMBER: _ClassVar[int]
    tid: int
    pid: int
    start_va: int
    state: int
    wait_reason: int
    base_priority: int
    win32_start_va: int
    teb: int
    context_regs: _containers.ScalarMap[str, int]
    def __init__(self, tid: _Optional[int] = ..., pid: _Optional[int] = ..., start_va: _Optional[int] = ..., state: _Optional[int] = ..., wait_reason: _Optional[int] = ..., base_priority: _Optional[int] = ..., win32_start_va: _Optional[int] = ..., teb: _Optional[int] = ..., context_regs: _Optional[_Mapping[str, int]] = ...) -> None: ...

class ThreadListResponse(_message.Message):
    __slots__ = ("status", "threads", "count", "truncated", "source")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    THREADS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    threads: _containers.RepeatedCompositeFieldContainer[SysThreadInfo]
    count: int
    truncated: bool
    source: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., threads: _Optional[_Iterable[_Union[SysThreadInfo, _Mapping]]] = ..., count: _Optional[int] = ..., truncated: _Optional[bool] = ..., source: _Optional[str] = ...) -> None: ...

class ObjEnumRequest(_message.Message):
    __slots__ = ("path", "depth", "max_entries")
    PATH_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    MAX_ENTRIES_FIELD_NUMBER: _ClassVar[int]
    path: str
    depth: int
    max_entries: int
    def __init__(self, path: _Optional[str] = ..., depth: _Optional[int] = ..., max_entries: _Optional[int] = ...) -> None: ...

class ObjEntry(_message.Message):
    __slots__ = ("name", "type", "address", "type_index", "source")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TYPE_INDEX_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    name: str
    type: str
    address: int
    type_index: int
    source: str
    def __init__(self, name: _Optional[str] = ..., type: _Optional[str] = ..., address: _Optional[int] = ..., type_index: _Optional[int] = ..., source: _Optional[str] = ...) -> None: ...

class ObjEnumResponse(_message.Message):
    __slots__ = ("status", "entries", "count", "truncated")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    entries: _containers.RepeatedCompositeFieldContainer[ObjEntry]
    count: int
    truncated: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., entries: _Optional[_Iterable[_Union[ObjEntry, _Mapping]]] = ..., count: _Optional[int] = ..., truncated: _Optional[bool] = ...) -> None: ...

class PryEvent(_message.Message):
    __slots__ = ("status", "seq", "ts_ms", "kind", "pid", "parent_pid", "tid", "image", "cmdline", "dropped", "address", "dr6", "bp_id", "slot", "access", "irql")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SEQ_FIELD_NUMBER: _ClassVar[int]
    TS_MS_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    PARENT_PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    CMDLINE_FIELD_NUMBER: _ClassVar[int]
    DROPPED_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DR6_FIELD_NUMBER: _ClassVar[int]
    BP_ID_FIELD_NUMBER: _ClassVar[int]
    SLOT_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    IRQL_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    seq: int
    ts_ms: int
    kind: EventsKind
    pid: int
    parent_pid: int
    tid: int
    image: str
    cmdline: str
    dropped: bool
    address: int
    dr6: int
    bp_id: int
    slot: int
    access: int
    irql: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., seq: _Optional[int] = ..., ts_ms: _Optional[int] = ..., kind: _Optional[_Union[EventsKind, str]] = ..., pid: _Optional[int] = ..., parent_pid: _Optional[int] = ..., tid: _Optional[int] = ..., image: _Optional[str] = ..., cmdline: _Optional[str] = ..., dropped: _Optional[bool] = ..., address: _Optional[int] = ..., dr6: _Optional[int] = ..., bp_id: _Optional[int] = ..., slot: _Optional[int] = ..., access: _Optional[int] = ..., irql: _Optional[int] = ...) -> None: ...

class EventsStreamRequest(_message.Message):
    __slots__ = ("kinds_mask", "interval_ms", "duration_s", "max_events", "dangerous_ok")
    KINDS_MASK_FIELD_NUMBER: _ClassVar[int]
    INTERVAL_MS_FIELD_NUMBER: _ClassVar[int]
    DURATION_S_FIELD_NUMBER: _ClassVar[int]
    MAX_EVENTS_FIELD_NUMBER: _ClassVar[int]
    DANGEROUS_OK_FIELD_NUMBER: _ClassVar[int]
    kinds_mask: int
    interval_ms: int
    duration_s: int
    max_events: int
    dangerous_ok: bool
    def __init__(self, kinds_mask: _Optional[int] = ..., interval_ms: _Optional[int] = ..., duration_s: _Optional[int] = ..., max_events: _Optional[int] = ..., dangerous_ok: _Optional[bool] = ...) -> None: ...

class EventsStreamChunk(_message.Message):
    __slots__ = ("status", "events", "dropped", "done")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    DROPPED_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    events: _containers.RepeatedCompositeFieldContainer[PryEvent]
    dropped: int
    done: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., events: _Optional[_Iterable[_Union[PryEvent, _Mapping]]] = ..., dropped: _Optional[int] = ..., done: _Optional[bool] = ...) -> None: ...

class EventsPollRequest(_message.Message):
    __slots__ = ("since_seq", "max_events", "kinds_mask", "dangerous_ok")
    SINCE_SEQ_FIELD_NUMBER: _ClassVar[int]
    MAX_EVENTS_FIELD_NUMBER: _ClassVar[int]
    KINDS_MASK_FIELD_NUMBER: _ClassVar[int]
    DANGEROUS_OK_FIELD_NUMBER: _ClassVar[int]
    since_seq: int
    max_events: int
    kinds_mask: int
    dangerous_ok: bool
    def __init__(self, since_seq: _Optional[int] = ..., max_events: _Optional[int] = ..., kinds_mask: _Optional[int] = ..., dangerous_ok: _Optional[bool] = ...) -> None: ...

class EventsPollResponse(_message.Message):
    __slots__ = ("status", "events", "last_seq", "dropped", "subscribed", "bp_hook")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    LAST_SEQ_FIELD_NUMBER: _ClassVar[int]
    DROPPED_FIELD_NUMBER: _ClassVar[int]
    SUBSCRIBED_FIELD_NUMBER: _ClassVar[int]
    BP_HOOK_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    events: _containers.RepeatedCompositeFieldContainer[PryEvent]
    last_seq: int
    dropped: int
    subscribed: bool
    bp_hook: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., events: _Optional[_Iterable[_Union[PryEvent, _Mapping]]] = ..., last_seq: _Optional[int] = ..., dropped: _Optional[int] = ..., subscribed: _Optional[bool] = ..., bp_hook: _Optional[bool] = ...) -> None: ...

class EventsStatsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EventsStatsResponse(_message.Message):
    __slots__ = ("status", "buffered", "dropped", "seq", "proc_notify", "image_notify", "thread_notify", "bp_hook", "bp_missed")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    BUFFERED_FIELD_NUMBER: _ClassVar[int]
    DROPPED_FIELD_NUMBER: _ClassVar[int]
    SEQ_FIELD_NUMBER: _ClassVar[int]
    PROC_NOTIFY_FIELD_NUMBER: _ClassVar[int]
    IMAGE_NOTIFY_FIELD_NUMBER: _ClassVar[int]
    THREAD_NOTIFY_FIELD_NUMBER: _ClassVar[int]
    BP_HOOK_FIELD_NUMBER: _ClassVar[int]
    BP_MISSED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    buffered: int
    dropped: int
    seq: int
    proc_notify: bool
    image_notify: bool
    thread_notify: bool
    bp_hook: bool
    bp_missed: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., buffered: _Optional[int] = ..., dropped: _Optional[int] = ..., seq: _Optional[int] = ..., proc_notify: _Optional[bool] = ..., image_notify: _Optional[bool] = ..., thread_notify: _Optional[bool] = ..., bp_hook: _Optional[bool] = ..., bp_missed: _Optional[int] = ...) -> None: ...

class MsrReadRequest(_message.Message):
    __slots__ = ("msr", "cores", "all_cores")
    MSR_FIELD_NUMBER: _ClassVar[int]
    CORES_FIELD_NUMBER: _ClassVar[int]
    ALL_CORES_FIELD_NUMBER: _ClassVar[int]
    msr: int
    cores: _containers.RepeatedScalarFieldContainer[int]
    all_cores: bool
    def __init__(self, msr: _Optional[int] = ..., cores: _Optional[_Iterable[int]] = ..., all_cores: _Optional[bool] = ...) -> None: ...

class MsrValue(_message.Message):
    __slots__ = ("core", "value", "nt_status")
    CORE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    NT_STATUS_FIELD_NUMBER: _ClassVar[int]
    core: int
    value: int
    nt_status: int
    def __init__(self, core: _Optional[int] = ..., value: _Optional[int] = ..., nt_status: _Optional[int] = ...) -> None: ...

class MsrReadResponse(_message.Message):
    __slots__ = ("status", "values")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    values: _containers.RepeatedCompositeFieldContainer[MsrValue]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., values: _Optional[_Iterable[_Union[MsrValue, _Mapping]]] = ...) -> None: ...

class CpuidRequest(_message.Message):
    __slots__ = ("leaf", "subleaf", "cores", "all_cores")
    LEAF_FIELD_NUMBER: _ClassVar[int]
    SUBLEAF_FIELD_NUMBER: _ClassVar[int]
    CORES_FIELD_NUMBER: _ClassVar[int]
    ALL_CORES_FIELD_NUMBER: _ClassVar[int]
    leaf: int
    subleaf: int
    cores: _containers.RepeatedScalarFieldContainer[int]
    all_cores: bool
    def __init__(self, leaf: _Optional[int] = ..., subleaf: _Optional[int] = ..., cores: _Optional[_Iterable[int]] = ..., all_cores: _Optional[bool] = ...) -> None: ...

class CpuidValue(_message.Message):
    __slots__ = ("core", "eax", "ebx", "ecx", "edx")
    CORE_FIELD_NUMBER: _ClassVar[int]
    EAX_FIELD_NUMBER: _ClassVar[int]
    EBX_FIELD_NUMBER: _ClassVar[int]
    ECX_FIELD_NUMBER: _ClassVar[int]
    EDX_FIELD_NUMBER: _ClassVar[int]
    core: int
    eax: int
    ebx: int
    ecx: int
    edx: int
    def __init__(self, core: _Optional[int] = ..., eax: _Optional[int] = ..., ebx: _Optional[int] = ..., ecx: _Optional[int] = ..., edx: _Optional[int] = ...) -> None: ...

class CpuidResponse(_message.Message):
    __slots__ = ("status", "values")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    values: _containers.RepeatedCompositeFieldContainer[CpuidValue]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., values: _Optional[_Iterable[_Union[CpuidValue, _Mapping]]] = ...) -> None: ...

class ImageCoherencyRequest(_message.Message):
    __slots__ = ("pid", "module_base", "module_name", "mode", "max_mismatch_ranges", "include_mismatch_hex")
    class Mode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        QUICK: _ClassVar[ImageCoherencyRequest.Mode]
        NORMAL: _ClassVar[ImageCoherencyRequest.Mode]
        FULL: _ClassVar[ImageCoherencyRequest.Mode]
    QUICK: ImageCoherencyRequest.Mode
    NORMAL: ImageCoherencyRequest.Mode
    FULL: ImageCoherencyRequest.Mode
    PID_FIELD_NUMBER: _ClassVar[int]
    MODULE_BASE_FIELD_NUMBER: _ClassVar[int]
    MODULE_NAME_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    MAX_MISMATCH_RANGES_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_MISMATCH_HEX_FIELD_NUMBER: _ClassVar[int]
    pid: int
    module_base: int
    module_name: str
    mode: ImageCoherencyRequest.Mode
    max_mismatch_ranges: int
    include_mismatch_hex: bool
    def __init__(self, pid: _Optional[int] = ..., module_base: _Optional[int] = ..., module_name: _Optional[str] = ..., mode: _Optional[_Union[ImageCoherencyRequest.Mode, str]] = ..., max_mismatch_ranges: _Optional[int] = ..., include_mismatch_hex: _Optional[bool] = ...) -> None: ...

class ImageCoherencyMismatch(_message.Message):
    __slots__ = ("rva", "length", "in_memory_sample", "on_disk_sample", "section", "hint")
    RVA_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    IN_MEMORY_SAMPLE_FIELD_NUMBER: _ClassVar[int]
    ON_DISK_SAMPLE_FIELD_NUMBER: _ClassVar[int]
    SECTION_FIELD_NUMBER: _ClassVar[int]
    HINT_FIELD_NUMBER: _ClassVar[int]
    rva: int
    length: int
    in_memory_sample: bytes
    on_disk_sample: bytes
    section: str
    hint: str
    def __init__(self, rva: _Optional[int] = ..., length: _Optional[int] = ..., in_memory_sample: _Optional[bytes] = ..., on_disk_sample: _Optional[bytes] = ..., section: _Optional[str] = ..., hint: _Optional[str] = ...) -> None: ...

class ImageCoherencyResponse(_message.Message):
    __slots__ = ("status", "module_basename", "module_path_disk", "size_of_image", "bytes_compared", "bytes_mismatched", "coherency", "classification", "ranges", "sections_total", "sections_skipped_relocatable", "truncated", "sections", "reloc_dir_rva", "reloc_dir_size")
    class SectionSpan(_message.Message):
        __slots__ = ("name", "va", "size", "characteristics")
        NAME_FIELD_NUMBER: _ClassVar[int]
        VA_FIELD_NUMBER: _ClassVar[int]
        SIZE_FIELD_NUMBER: _ClassVar[int]
        CHARACTERISTICS_FIELD_NUMBER: _ClassVar[int]
        name: str
        va: int
        size: int
        characteristics: int
        def __init__(self, name: _Optional[str] = ..., va: _Optional[int] = ..., size: _Optional[int] = ..., characteristics: _Optional[int] = ...) -> None: ...
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MODULE_BASENAME_FIELD_NUMBER: _ClassVar[int]
    MODULE_PATH_DISK_FIELD_NUMBER: _ClassVar[int]
    SIZE_OF_IMAGE_FIELD_NUMBER: _ClassVar[int]
    BYTES_COMPARED_FIELD_NUMBER: _ClassVar[int]
    BYTES_MISMATCHED_FIELD_NUMBER: _ClassVar[int]
    COHERENCY_FIELD_NUMBER: _ClassVar[int]
    CLASSIFICATION_FIELD_NUMBER: _ClassVar[int]
    RANGES_FIELD_NUMBER: _ClassVar[int]
    SECTIONS_TOTAL_FIELD_NUMBER: _ClassVar[int]
    SECTIONS_SKIPPED_RELOCATABLE_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    SECTIONS_FIELD_NUMBER: _ClassVar[int]
    RELOC_DIR_RVA_FIELD_NUMBER: _ClassVar[int]
    RELOC_DIR_SIZE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    module_basename: str
    module_path_disk: str
    size_of_image: int
    bytes_compared: int
    bytes_mismatched: int
    coherency: float
    classification: str
    ranges: _containers.RepeatedCompositeFieldContainer[ImageCoherencyMismatch]
    sections_total: int
    sections_skipped_relocatable: int
    truncated: bool
    sections: _containers.RepeatedCompositeFieldContainer[ImageCoherencyResponse.SectionSpan]
    reloc_dir_rva: int
    reloc_dir_size: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., module_basename: _Optional[str] = ..., module_path_disk: _Optional[str] = ..., size_of_image: _Optional[int] = ..., bytes_compared: _Optional[int] = ..., bytes_mismatched: _Optional[int] = ..., coherency: _Optional[float] = ..., classification: _Optional[str] = ..., ranges: _Optional[_Iterable[_Union[ImageCoherencyMismatch, _Mapping]]] = ..., sections_total: _Optional[int] = ..., sections_skipped_relocatable: _Optional[int] = ..., truncated: _Optional[bool] = ..., sections: _Optional[_Iterable[_Union[ImageCoherencyResponse.SectionSpan, _Mapping]]] = ..., reloc_dir_rva: _Optional[int] = ..., reloc_dir_size: _Optional[int] = ...) -> None: ...

class SelfProtConfigRequest(_message.Message):
    __slots__ = ("enable", "flags", "process_access_keep", "thread_access_keep", "protected_pids", "disable_token")
    ENABLE_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    PROCESS_ACCESS_KEEP_FIELD_NUMBER: _ClassVar[int]
    THREAD_ACCESS_KEEP_FIELD_NUMBER: _ClassVar[int]
    PROTECTED_PIDS_FIELD_NUMBER: _ClassVar[int]
    DISABLE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    enable: int
    flags: int
    process_access_keep: int
    thread_access_keep: int
    protected_pids: _containers.RepeatedScalarFieldContainer[int]
    disable_token: int
    def __init__(self, enable: _Optional[int] = ..., flags: _Optional[int] = ..., process_access_keep: _Optional[int] = ..., thread_access_keep: _Optional[int] = ..., protected_pids: _Optional[_Iterable[int]] = ..., disable_token: _Optional[int] = ...) -> None: ...

class SelfProtConfigResponse(_message.Message):
    __slots__ = ("status", "state", "installed", "altitude", "protected_pids", "disable_token")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    INSTALLED_FIELD_NUMBER: _ClassVar[int]
    ALTITUDE_FIELD_NUMBER: _ClassVar[int]
    PROTECTED_PIDS_FIELD_NUMBER: _ClassVar[int]
    DISABLE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    state: int
    installed: bool
    altitude: int
    protected_pids: int
    disable_token: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., state: _Optional[int] = ..., installed: _Optional[bool] = ..., altitude: _Optional[int] = ..., protected_pids: _Optional[int] = ..., disable_token: _Optional[int] = ...) -> None: ...

class SelfProtStatusRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SelfProtStatusResponse(_message.Message):
    __slots__ = ("status", "state", "installed", "altitude", "protected_pids", "flags", "process_access_keep", "thread_access_keep", "preop_hits", "stripped", "bypassed")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    INSTALLED_FIELD_NUMBER: _ClassVar[int]
    ALTITUDE_FIELD_NUMBER: _ClassVar[int]
    PROTECTED_PIDS_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    PROCESS_ACCESS_KEEP_FIELD_NUMBER: _ClassVar[int]
    THREAD_ACCESS_KEEP_FIELD_NUMBER: _ClassVar[int]
    PREOP_HITS_FIELD_NUMBER: _ClassVar[int]
    STRIPPED_FIELD_NUMBER: _ClassVar[int]
    BYPASSED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    state: int
    installed: bool
    altitude: int
    protected_pids: int
    flags: int
    process_access_keep: int
    thread_access_keep: int
    preop_hits: int
    stripped: int
    bypassed: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., state: _Optional[int] = ..., installed: _Optional[bool] = ..., altitude: _Optional[int] = ..., protected_pids: _Optional[int] = ..., flags: _Optional[int] = ..., process_access_keep: _Optional[int] = ..., thread_access_keep: _Optional[int] = ..., preop_hits: _Optional[int] = ..., stripped: _Optional[int] = ..., bypassed: _Optional[int] = ...) -> None: ...

class VerifySignaturesRequest(_message.Message):
    __slots__ = ("paths", "force_recheck")
    PATHS_FIELD_NUMBER: _ClassVar[int]
    FORCE_RECHECK_FIELD_NUMBER: _ClassVar[int]
    paths: _containers.RepeatedScalarFieldContainer[str]
    force_recheck: bool
    def __init__(self, paths: _Optional[_Iterable[str]] = ..., force_recheck: _Optional[bool] = ...) -> None: ...

class SignerRow(_message.Message):
    __slots__ = ("path", "signer", "issuer", "signing_level", "is_signed", "catalog", "cache_timestamp_100ns", "cache_hit", "error")
    PATH_FIELD_NUMBER: _ClassVar[int]
    SIGNER_FIELD_NUMBER: _ClassVar[int]
    ISSUER_FIELD_NUMBER: _ClassVar[int]
    SIGNING_LEVEL_FIELD_NUMBER: _ClassVar[int]
    IS_SIGNED_FIELD_NUMBER: _ClassVar[int]
    CATALOG_FIELD_NUMBER: _ClassVar[int]
    CACHE_TIMESTAMP_100NS_FIELD_NUMBER: _ClassVar[int]
    CACHE_HIT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    path: str
    signer: str
    issuer: str
    signing_level: str
    is_signed: bool
    catalog: bool
    cache_timestamp_100ns: int
    cache_hit: bool
    error: str
    def __init__(self, path: _Optional[str] = ..., signer: _Optional[str] = ..., issuer: _Optional[str] = ..., signing_level: _Optional[str] = ..., is_signed: _Optional[bool] = ..., catalog: _Optional[bool] = ..., cache_timestamp_100ns: _Optional[int] = ..., cache_hit: _Optional[bool] = ..., error: _Optional[str] = ...) -> None: ...

class VerifySignaturesResponse(_message.Message):
    __slots__ = ("status", "rows", "cache_hits", "probed")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    CACHE_HITS_FIELD_NUMBER: _ClassVar[int]
    PROBED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    rows: _containers.RepeatedCompositeFieldContainer[SignerRow]
    cache_hits: int
    probed: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., rows: _Optional[_Iterable[_Union[SignerRow, _Mapping]]] = ..., cache_hits: _Optional[int] = ..., probed: _Optional[int] = ...) -> None: ...

class WatchHwAddRequest(_message.Message):
    __slots__ = ("pid", "tid", "address", "size", "access", "slot", "preempt_ok", "tag")
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    SLOT_FIELD_NUMBER: _ClassVar[int]
    PREEMPT_OK_FIELD_NUMBER: _ClassVar[int]
    TAG_FIELD_NUMBER: _ClassVar[int]
    pid: int
    tid: int
    address: int
    size: int
    access: str
    slot: int
    preempt_ok: bool
    tag: str
    def __init__(self, pid: _Optional[int] = ..., tid: _Optional[int] = ..., address: _Optional[int] = ..., size: _Optional[int] = ..., access: _Optional[str] = ..., slot: _Optional[int] = ..., preempt_ok: _Optional[bool] = ..., tag: _Optional[str] = ...) -> None: ...

class WatchHwAddResponse(_message.Message):
    __slots__ = ("status", "watch_cookie", "slot", "threads_patched", "hvci_fallback")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    WATCH_COOKIE_FIELD_NUMBER: _ClassVar[int]
    SLOT_FIELD_NUMBER: _ClassVar[int]
    THREADS_PATCHED_FIELD_NUMBER: _ClassVar[int]
    HVCI_FALLBACK_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    watch_cookie: int
    slot: int
    threads_patched: int
    hvci_fallback: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., watch_cookie: _Optional[int] = ..., slot: _Optional[int] = ..., threads_patched: _Optional[int] = ..., hvci_fallback: _Optional[bool] = ...) -> None: ...

class WatchHwRemoveRequest(_message.Message):
    __slots__ = ("watch_cookie",)
    WATCH_COOKIE_FIELD_NUMBER: _ClassVar[int]
    watch_cookie: int
    def __init__(self, watch_cookie: _Optional[int] = ...) -> None: ...

class ProcessDumpRequest(_message.Message):
    __slots__ = ("pid", "flags", "output_path", "use_snapshot")
    PID_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_PATH_FIELD_NUMBER: _ClassVar[int]
    USE_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    pid: int
    flags: int
    output_path: str
    use_snapshot: bool
    def __init__(self, pid: _Optional[int] = ..., flags: _Optional[int] = ..., output_path: _Optional[str] = ..., use_snapshot: _Optional[bool] = ...) -> None: ...

class ProcessDumpResponse(_message.Message):
    __slots__ = ("status", "path", "size", "sha256", "access_mask_used", "snapshot_used", "kind")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    ACCESS_MASK_USED_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_USED_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    path: str
    size: int
    sha256: str
    access_mask_used: int
    snapshot_used: bool
    kind: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., path: _Optional[str] = ..., size: _Optional[int] = ..., sha256: _Optional[str] = ..., access_mask_used: _Optional[int] = ..., snapshot_used: _Optional[bool] = ..., kind: _Optional[str] = ...) -> None: ...

class CreateLiveKernelDumpRequest(_message.Message):
    __slots__ = ("output_path", "flags", "compression", "allow_cancel")
    OUTPUT_PATH_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    COMPRESSION_FIELD_NUMBER: _ClassVar[int]
    ALLOW_CANCEL_FIELD_NUMBER: _ClassVar[int]
    output_path: str
    flags: _containers.RepeatedScalarFieldContainer[str]
    compression: bool
    allow_cancel: bool
    def __init__(self, output_path: _Optional[str] = ..., flags: _Optional[_Iterable[str]] = ..., compression: _Optional[bool] = ..., allow_cancel: _Optional[bool] = ...) -> None: ...

class CreateLiveKernelDumpResponse(_message.Message):
    __slots__ = ("status", "path", "size", "sha256", "flags_used_mask", "flags_unknown", "kind", "error_detail")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    FLAGS_USED_MASK_FIELD_NUMBER: _ClassVar[int]
    FLAGS_UNKNOWN_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ERROR_DETAIL_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    path: str
    size: int
    sha256: str
    flags_used_mask: int
    flags_unknown: _containers.RepeatedScalarFieldContainer[str]
    kind: str
    error_detail: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., path: _Optional[str] = ..., size: _Optional[int] = ..., sha256: _Optional[str] = ..., flags_used_mask: _Optional[int] = ..., flags_unknown: _Optional[_Iterable[str]] = ..., kind: _Optional[str] = ..., error_detail: _Optional[str] = ...) -> None: ...

class EtwStartRequest(_message.Message):
    __slots__ = ("session_name", "providers", "keywords_any", "keywords_all", "level", "buffer_size_kb", "min_buffers", "max_buffers", "ring_capacity")
    SESSION_NAME_FIELD_NUMBER: _ClassVar[int]
    PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    KEYWORDS_ANY_FIELD_NUMBER: _ClassVar[int]
    KEYWORDS_ALL_FIELD_NUMBER: _ClassVar[int]
    LEVEL_FIELD_NUMBER: _ClassVar[int]
    BUFFER_SIZE_KB_FIELD_NUMBER: _ClassVar[int]
    MIN_BUFFERS_FIELD_NUMBER: _ClassVar[int]
    MAX_BUFFERS_FIELD_NUMBER: _ClassVar[int]
    RING_CAPACITY_FIELD_NUMBER: _ClassVar[int]
    session_name: str
    providers: _containers.RepeatedScalarFieldContainer[str]
    keywords_any: int
    keywords_all: int
    level: int
    buffer_size_kb: int
    min_buffers: int
    max_buffers: int
    ring_capacity: int
    def __init__(self, session_name: _Optional[str] = ..., providers: _Optional[_Iterable[str]] = ..., keywords_any: _Optional[int] = ..., keywords_all: _Optional[int] = ..., level: _Optional[int] = ..., buffer_size_kb: _Optional[int] = ..., min_buffers: _Optional[int] = ..., max_buffers: _Optional[int] = ..., ring_capacity: _Optional[int] = ...) -> None: ...

class EtwStartResponse(_message.Message):
    __slots__ = ("status", "session_name", "session_handle", "started_providers", "failed_providers", "ring_capacity")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SESSION_NAME_FIELD_NUMBER: _ClassVar[int]
    SESSION_HANDLE_FIELD_NUMBER: _ClassVar[int]
    STARTED_PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    FAILED_PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    RING_CAPACITY_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    session_name: str
    session_handle: int
    started_providers: _containers.RepeatedScalarFieldContainer[str]
    failed_providers: _containers.RepeatedScalarFieldContainer[str]
    ring_capacity: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., session_name: _Optional[str] = ..., session_handle: _Optional[int] = ..., started_providers: _Optional[_Iterable[str]] = ..., failed_providers: _Optional[_Iterable[str]] = ..., ring_capacity: _Optional[int] = ...) -> None: ...

class EtwStopRequest(_message.Message):
    __slots__ = ("session_name",)
    SESSION_NAME_FIELD_NUMBER: _ClassVar[int]
    session_name: str
    def __init__(self, session_name: _Optional[str] = ...) -> None: ...

class EtwStopResponse(_message.Message):
    __slots__ = ("status", "events_total", "events_dropped")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EVENTS_TOTAL_FIELD_NUMBER: _ClassVar[int]
    EVENTS_DROPPED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    events_total: int
    events_dropped: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., events_total: _Optional[int] = ..., events_dropped: _Optional[int] = ...) -> None: ...

class EtwTraceSessionRow(_message.Message):
    __slots__ = ("session_name", "events_total", "events_dropped", "providers", "running")
    SESSION_NAME_FIELD_NUMBER: _ClassVar[int]
    EVENTS_TOTAL_FIELD_NUMBER: _ClassVar[int]
    EVENTS_DROPPED_FIELD_NUMBER: _ClassVar[int]
    PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    RUNNING_FIELD_NUMBER: _ClassVar[int]
    session_name: str
    events_total: int
    events_dropped: int
    providers: int
    running: bool
    def __init__(self, session_name: _Optional[str] = ..., events_total: _Optional[int] = ..., events_dropped: _Optional[int] = ..., providers: _Optional[int] = ..., running: _Optional[bool] = ...) -> None: ...

class EtwTraceSessionsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EtwTraceSessionsResponse(_message.Message):
    __slots__ = ("status", "sessions")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SESSIONS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    sessions: _containers.RepeatedCompositeFieldContainer[EtwTraceSessionRow]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., sessions: _Optional[_Iterable[_Union[EtwTraceSessionRow, _Mapping]]] = ...) -> None: ...

class EtwEventRow(_message.Message):
    __slots__ = ("seq", "ts_100ns", "provider_guid", "event_id", "pid", "tid", "opcode", "version", "level", "keywords", "kind", "fields")
    class FieldsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SEQ_FIELD_NUMBER: _ClassVar[int]
    TS_100NS_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_GUID_FIELD_NUMBER: _ClassVar[int]
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    OPCODE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    LEVEL_FIELD_NUMBER: _ClassVar[int]
    KEYWORDS_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    seq: int
    ts_100ns: int
    provider_guid: str
    event_id: int
    pid: int
    tid: int
    opcode: int
    version: int
    level: int
    keywords: int
    kind: str
    fields: _containers.ScalarMap[str, str]
    def __init__(self, seq: _Optional[int] = ..., ts_100ns: _Optional[int] = ..., provider_guid: _Optional[str] = ..., event_id: _Optional[int] = ..., pid: _Optional[int] = ..., tid: _Optional[int] = ..., opcode: _Optional[int] = ..., version: _Optional[int] = ..., level: _Optional[int] = ..., keywords: _Optional[int] = ..., kind: _Optional[str] = ..., fields: _Optional[_Mapping[str, str]] = ...) -> None: ...

class EtwTailRequest(_message.Message):
    __slots__ = ("session_name", "since_seq", "limit")
    SESSION_NAME_FIELD_NUMBER: _ClassVar[int]
    SINCE_SEQ_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    session_name: str
    since_seq: int
    limit: int
    def __init__(self, session_name: _Optional[str] = ..., since_seq: _Optional[int] = ..., limit: _Optional[int] = ...) -> None: ...

class EtwTailResponse(_message.Message):
    __slots__ = ("status", "events", "last_seq", "dropped")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    LAST_SEQ_FIELD_NUMBER: _ClassVar[int]
    DROPPED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    events: _containers.RepeatedCompositeFieldContainer[EtwEventRow]
    last_seq: int
    dropped: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., events: _Optional[_Iterable[_Union[EtwEventRow, _Mapping]]] = ..., last_seq: _Optional[int] = ..., dropped: _Optional[int] = ...) -> None: ...

class EtwEventsRequest(_message.Message):
    __slots__ = ("session_name", "max_events", "timeout_ms")
    SESSION_NAME_FIELD_NUMBER: _ClassVar[int]
    MAX_EVENTS_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    session_name: str
    max_events: int
    timeout_ms: int
    def __init__(self, session_name: _Optional[str] = ..., max_events: _Optional[int] = ..., timeout_ms: _Optional[int] = ...) -> None: ...

class EtwEventsResponse(_message.Message):
    __slots__ = ("status", "events", "last_seq", "dropped")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    LAST_SEQ_FIELD_NUMBER: _ClassVar[int]
    DROPPED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    events: _containers.RepeatedCompositeFieldContainer[EtwEventRow]
    last_seq: int
    dropped: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., events: _Optional[_Iterable[_Union[EtwEventRow, _Mapping]]] = ..., last_seq: _Optional[int] = ..., dropped: _Optional[int] = ...) -> None: ...

class EtwStatsRequest(_message.Message):
    __slots__ = ("session_name",)
    SESSION_NAME_FIELD_NUMBER: _ClassVar[int]
    session_name: str
    def __init__(self, session_name: _Optional[str] = ...) -> None: ...

class EtwStatsResponse(_message.Message):
    __slots__ = ("status", "session_name", "events_total", "events_dropped", "events_lost", "buffers_written", "buffers_lost", "ring_capacity", "ring_used", "running")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SESSION_NAME_FIELD_NUMBER: _ClassVar[int]
    EVENTS_TOTAL_FIELD_NUMBER: _ClassVar[int]
    EVENTS_DROPPED_FIELD_NUMBER: _ClassVar[int]
    EVENTS_LOST_FIELD_NUMBER: _ClassVar[int]
    BUFFERS_WRITTEN_FIELD_NUMBER: _ClassVar[int]
    BUFFERS_LOST_FIELD_NUMBER: _ClassVar[int]
    RING_CAPACITY_FIELD_NUMBER: _ClassVar[int]
    RING_USED_FIELD_NUMBER: _ClassVar[int]
    RUNNING_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    session_name: str
    events_total: int
    events_dropped: int
    events_lost: int
    buffers_written: int
    buffers_lost: int
    ring_capacity: int
    ring_used: int
    running: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., session_name: _Optional[str] = ..., events_total: _Optional[int] = ..., events_dropped: _Optional[int] = ..., events_lost: _Optional[int] = ..., buffers_written: _Optional[int] = ..., buffers_lost: _Optional[int] = ..., ring_capacity: _Optional[int] = ..., ring_used: _Optional[int] = ..., running: _Optional[bool] = ...) -> None: ...

class HandleDupRequest(_message.Message):
    __slots__ = ("src_pid", "src_handle", "desired_access", "options", "privilege_cookie")
    SRC_PID_FIELD_NUMBER: _ClassVar[int]
    SRC_HANDLE_FIELD_NUMBER: _ClassVar[int]
    DESIRED_ACCESS_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    PRIVILEGE_COOKIE_FIELD_NUMBER: _ClassVar[int]
    src_pid: int
    src_handle: int
    desired_access: int
    options: int
    privilege_cookie: int
    def __init__(self, src_pid: _Optional[int] = ..., src_handle: _Optional[int] = ..., desired_access: _Optional[int] = ..., options: _Optional[int] = ..., privilege_cookie: _Optional[int] = ...) -> None: ...

class HandleDupResponse(_message.Message):
    __slots__ = ("status", "new_handle", "object_addr", "granted_access", "type_index", "type_name")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    NEW_HANDLE_FIELD_NUMBER: _ClassVar[int]
    OBJECT_ADDR_FIELD_NUMBER: _ClassVar[int]
    GRANTED_ACCESS_FIELD_NUMBER: _ClassVar[int]
    TYPE_INDEX_FIELD_NUMBER: _ClassVar[int]
    TYPE_NAME_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    new_handle: int
    object_addr: int
    granted_access: int
    type_index: int
    type_name: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., new_handle: _Optional[int] = ..., object_addr: _Optional[int] = ..., granted_access: _Optional[int] = ..., type_index: _Optional[int] = ..., type_name: _Optional[str] = ...) -> None: ...

class HandleCloseRemoteRequest(_message.Message):
    __slots__ = ("target_pid", "target_handle", "privilege_cookie")
    TARGET_PID_FIELD_NUMBER: _ClassVar[int]
    TARGET_HANDLE_FIELD_NUMBER: _ClassVar[int]
    PRIVILEGE_COOKIE_FIELD_NUMBER: _ClassVar[int]
    target_pid: int
    target_handle: int
    privilege_cookie: int
    def __init__(self, target_pid: _Optional[int] = ..., target_handle: _Optional[int] = ..., privilege_cookie: _Optional[int] = ...) -> None: ...

class HandleCloseRemoteResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ...) -> None: ...

class HandleCompareRequest(_message.Message):
    __slots__ = ("pid_a", "handle_a", "pid_b", "handle_b", "privilege_cookie")
    PID_A_FIELD_NUMBER: _ClassVar[int]
    HANDLE_A_FIELD_NUMBER: _ClassVar[int]
    PID_B_FIELD_NUMBER: _ClassVar[int]
    HANDLE_B_FIELD_NUMBER: _ClassVar[int]
    PRIVILEGE_COOKIE_FIELD_NUMBER: _ClassVar[int]
    pid_a: int
    handle_a: int
    pid_b: int
    handle_b: int
    privilege_cookie: int
    def __init__(self, pid_a: _Optional[int] = ..., handle_a: _Optional[int] = ..., pid_b: _Optional[int] = ..., handle_b: _Optional[int] = ..., privilege_cookie: _Optional[int] = ...) -> None: ...

class HandleCompareResponse(_message.Message):
    __slots__ = ("status", "same", "object_a", "object_b", "type_index_a", "type_index_b")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SAME_FIELD_NUMBER: _ClassVar[int]
    OBJECT_A_FIELD_NUMBER: _ClassVar[int]
    OBJECT_B_FIELD_NUMBER: _ClassVar[int]
    TYPE_INDEX_A_FIELD_NUMBER: _ClassVar[int]
    TYPE_INDEX_B_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    same: bool
    object_a: int
    object_b: int
    type_index_a: int
    type_index_b: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., same: _Optional[bool] = ..., object_a: _Optional[int] = ..., object_b: _Optional[int] = ..., type_index_a: _Optional[int] = ..., type_index_b: _Optional[int] = ...) -> None: ...

class StackWalkRequest(_message.Message):
    __slots__ = ("tid", "max_frames", "flags", "timeout_ms", "privilege_cookie")
    TID_FIELD_NUMBER: _ClassVar[int]
    MAX_FRAMES_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    PRIVILEGE_COOKIE_FIELD_NUMBER: _ClassVar[int]
    tid: int
    max_frames: int
    flags: int
    timeout_ms: int
    privilege_cookie: int
    def __init__(self, tid: _Optional[int] = ..., max_frames: _Optional[int] = ..., flags: _Optional[int] = ..., timeout_ms: _Optional[int] = ..., privilege_cookie: _Optional[int] = ...) -> None: ...

class StackWalkFrame(_message.Message):
    __slots__ = ("rip", "module_tag", "module_base")
    RIP_FIELD_NUMBER: _ClassVar[int]
    MODULE_TAG_FIELD_NUMBER: _ClassVar[int]
    MODULE_BASE_FIELD_NUMBER: _ClassVar[int]
    rip: int
    module_tag: int
    module_base: int
    def __init__(self, rip: _Optional[int] = ..., module_tag: _Optional[int] = ..., module_base: _Optional[int] = ...) -> None: ...

class StackWalkResponse(_message.Message):
    __slots__ = ("status", "pid", "flags", "rip", "rsp", "kernel_frames", "user_frames")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    RIP_FIELD_NUMBER: _ClassVar[int]
    RSP_FIELD_NUMBER: _ClassVar[int]
    KERNEL_FRAMES_FIELD_NUMBER: _ClassVar[int]
    USER_FRAMES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    pid: int
    flags: int
    rip: int
    rsp: int
    kernel_frames: _containers.RepeatedCompositeFieldContainer[StackWalkFrame]
    user_frames: _containers.RepeatedCompositeFieldContainer[StackWalkFrame]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., pid: _Optional[int] = ..., flags: _Optional[int] = ..., rip: _Optional[int] = ..., rsp: _Optional[int] = ..., kernel_frames: _Optional[_Iterable[_Union[StackWalkFrame, _Mapping]]] = ..., user_frames: _Optional[_Iterable[_Union[StackWalkFrame, _Mapping]]] = ...) -> None: ...

class HiddenProcessRequest(_message.Message):
    __slots__ = ("pid_max", "step", "modes", "timeout_ms")
    PID_MAX_FIELD_NUMBER: _ClassVar[int]
    STEP_FIELD_NUMBER: _ClassVar[int]
    MODES_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    pid_max: int
    step: int
    modes: _containers.RepeatedScalarFieldContainer[str]
    timeout_ms: int
    def __init__(self, pid_max: _Optional[int] = ..., step: _Optional[int] = ..., modes: _Optional[_Iterable[str]] = ..., timeout_ms: _Optional[int] = ...) -> None: ...

class HiddenPidRow(_message.Message):
    __slots__ = ("pid", "image", "present_brute", "present_registry", "present_etw", "exit_time_100ns", "handle_count", "sources")
    PID_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    PRESENT_BRUTE_FIELD_NUMBER: _ClassVar[int]
    PRESENT_REGISTRY_FIELD_NUMBER: _ClassVar[int]
    PRESENT_ETW_FIELD_NUMBER: _ClassVar[int]
    EXIT_TIME_100NS_FIELD_NUMBER: _ClassVar[int]
    HANDLE_COUNT_FIELD_NUMBER: _ClassVar[int]
    SOURCES_FIELD_NUMBER: _ClassVar[int]
    pid: int
    image: str
    present_brute: bool
    present_registry: bool
    present_etw: bool
    exit_time_100ns: int
    handle_count: int
    sources: str
    def __init__(self, pid: _Optional[int] = ..., image: _Optional[str] = ..., present_brute: _Optional[bool] = ..., present_registry: _Optional[bool] = ..., present_etw: _Optional[bool] = ..., exit_time_100ns: _Optional[int] = ..., handle_count: _Optional[int] = ..., sources: _Optional[str] = ...) -> None: ...

class HiddenProcessResponse(_message.Message):
    __slots__ = ("status", "rows", "modes_run", "modes_failed", "pid_max_used", "step_used")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    MODES_RUN_FIELD_NUMBER: _ClassVar[int]
    MODES_FAILED_FIELD_NUMBER: _ClassVar[int]
    PID_MAX_USED_FIELD_NUMBER: _ClassVar[int]
    STEP_USED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    rows: _containers.RepeatedCompositeFieldContainer[HiddenPidRow]
    modes_run: _containers.RepeatedScalarFieldContainer[str]
    modes_failed: _containers.RepeatedScalarFieldContainer[str]
    pid_max_used: int
    step_used: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., rows: _Optional[_Iterable[_Union[HiddenPidRow, _Mapping]]] = ..., modes_run: _Optional[_Iterable[str]] = ..., modes_failed: _Optional[_Iterable[str]] = ..., pid_max_used: _Optional[int] = ..., step_used: _Optional[int] = ...) -> None: ...

class TokenCore(_message.Message):
    __slots__ = ("user_sid", "user_name", "user_domain", "logon_sid", "integrity_rid", "integrity_name", "elevation_type", "is_elevated", "linked_token_present", "uac_virtualization_enabled", "uac_virtualization_allowed", "mandatory_policy", "session_id", "logon_id_low", "logon_id_high", "is_app_container", "app_container_sid", "app_container_name", "app_container_number", "trust_label_sid", "trust_label_name")
    USER_SID_FIELD_NUMBER: _ClassVar[int]
    USER_NAME_FIELD_NUMBER: _ClassVar[int]
    USER_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    LOGON_SID_FIELD_NUMBER: _ClassVar[int]
    INTEGRITY_RID_FIELD_NUMBER: _ClassVar[int]
    INTEGRITY_NAME_FIELD_NUMBER: _ClassVar[int]
    ELEVATION_TYPE_FIELD_NUMBER: _ClassVar[int]
    IS_ELEVATED_FIELD_NUMBER: _ClassVar[int]
    LINKED_TOKEN_PRESENT_FIELD_NUMBER: _ClassVar[int]
    UAC_VIRTUALIZATION_ENABLED_FIELD_NUMBER: _ClassVar[int]
    UAC_VIRTUALIZATION_ALLOWED_FIELD_NUMBER: _ClassVar[int]
    MANDATORY_POLICY_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    LOGON_ID_LOW_FIELD_NUMBER: _ClassVar[int]
    LOGON_ID_HIGH_FIELD_NUMBER: _ClassVar[int]
    IS_APP_CONTAINER_FIELD_NUMBER: _ClassVar[int]
    APP_CONTAINER_SID_FIELD_NUMBER: _ClassVar[int]
    APP_CONTAINER_NAME_FIELD_NUMBER: _ClassVar[int]
    APP_CONTAINER_NUMBER_FIELD_NUMBER: _ClassVar[int]
    TRUST_LABEL_SID_FIELD_NUMBER: _ClassVar[int]
    TRUST_LABEL_NAME_FIELD_NUMBER: _ClassVar[int]
    user_sid: str
    user_name: str
    user_domain: str
    logon_sid: str
    integrity_rid: int
    integrity_name: str
    elevation_type: str
    is_elevated: bool
    linked_token_present: bool
    uac_virtualization_enabled: bool
    uac_virtualization_allowed: bool
    mandatory_policy: int
    session_id: int
    logon_id_low: int
    logon_id_high: int
    is_app_container: bool
    app_container_sid: str
    app_container_name: str
    app_container_number: int
    trust_label_sid: str
    trust_label_name: str
    def __init__(self, user_sid: _Optional[str] = ..., user_name: _Optional[str] = ..., user_domain: _Optional[str] = ..., logon_sid: _Optional[str] = ..., integrity_rid: _Optional[int] = ..., integrity_name: _Optional[str] = ..., elevation_type: _Optional[str] = ..., is_elevated: _Optional[bool] = ..., linked_token_present: _Optional[bool] = ..., uac_virtualization_enabled: _Optional[bool] = ..., uac_virtualization_allowed: _Optional[bool] = ..., mandatory_policy: _Optional[int] = ..., session_id: _Optional[int] = ..., logon_id_low: _Optional[int] = ..., logon_id_high: _Optional[int] = ..., is_app_container: _Optional[bool] = ..., app_container_sid: _Optional[str] = ..., app_container_name: _Optional[str] = ..., app_container_number: _Optional[int] = ..., trust_label_sid: _Optional[str] = ..., trust_label_name: _Optional[str] = ...) -> None: ...

class TokenGroup(_message.Message):
    __slots__ = ("sid", "name", "domain", "attributes", "is_deny", "is_mandatory", "is_integrity", "is_logon_id", "is_enabled", "is_enabled_by_default", "is_use_for_deny_only", "is_owner", "is_resource", "use")
    SID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    IS_DENY_FIELD_NUMBER: _ClassVar[int]
    IS_MANDATORY_FIELD_NUMBER: _ClassVar[int]
    IS_INTEGRITY_FIELD_NUMBER: _ClassVar[int]
    IS_LOGON_ID_FIELD_NUMBER: _ClassVar[int]
    IS_ENABLED_FIELD_NUMBER: _ClassVar[int]
    IS_ENABLED_BY_DEFAULT_FIELD_NUMBER: _ClassVar[int]
    IS_USE_FOR_DENY_ONLY_FIELD_NUMBER: _ClassVar[int]
    IS_OWNER_FIELD_NUMBER: _ClassVar[int]
    IS_RESOURCE_FIELD_NUMBER: _ClassVar[int]
    USE_FIELD_NUMBER: _ClassVar[int]
    sid: str
    name: str
    domain: str
    attributes: int
    is_deny: bool
    is_mandatory: bool
    is_integrity: bool
    is_logon_id: bool
    is_enabled: bool
    is_enabled_by_default: bool
    is_use_for_deny_only: bool
    is_owner: bool
    is_resource: bool
    use: str
    def __init__(self, sid: _Optional[str] = ..., name: _Optional[str] = ..., domain: _Optional[str] = ..., attributes: _Optional[int] = ..., is_deny: _Optional[bool] = ..., is_mandatory: _Optional[bool] = ..., is_integrity: _Optional[bool] = ..., is_logon_id: _Optional[bool] = ..., is_enabled: _Optional[bool] = ..., is_enabled_by_default: _Optional[bool] = ..., is_use_for_deny_only: _Optional[bool] = ..., is_owner: _Optional[bool] = ..., is_resource: _Optional[bool] = ..., use: _Optional[str] = ...) -> None: ...

class TokenPrivilege(_message.Message):
    __slots__ = ("luid_low", "luid_high", "name", "display_name", "attributes", "state", "enabled_by_default")
    LUID_LOW_FIELD_NUMBER: _ClassVar[int]
    LUID_HIGH_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    ENABLED_BY_DEFAULT_FIELD_NUMBER: _ClassVar[int]
    luid_low: int
    luid_high: int
    name: str
    display_name: str
    attributes: int
    state: str
    enabled_by_default: bool
    def __init__(self, luid_low: _Optional[int] = ..., luid_high: _Optional[int] = ..., name: _Optional[str] = ..., display_name: _Optional[str] = ..., attributes: _Optional[int] = ..., state: _Optional[str] = ..., enabled_by_default: _Optional[bool] = ...) -> None: ...

class TokenCapability(_message.Message):
    __slots__ = ("sid", "name")
    SID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    sid: str
    name: str
    def __init__(self, sid: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class LogonSessionInfo(_message.Message):
    __slots__ = ("logon_id_low", "logon_id_high", "user_name", "auth_domain", "logon_type", "logon_type_name", "session_id", "logon_time_100ns", "logoff_time_100ns", "logon_server", "dns_domain_name", "upn", "user_flags")
    LOGON_ID_LOW_FIELD_NUMBER: _ClassVar[int]
    LOGON_ID_HIGH_FIELD_NUMBER: _ClassVar[int]
    USER_NAME_FIELD_NUMBER: _ClassVar[int]
    AUTH_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    LOGON_TYPE_FIELD_NUMBER: _ClassVar[int]
    LOGON_TYPE_NAME_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    LOGON_TIME_100NS_FIELD_NUMBER: _ClassVar[int]
    LOGOFF_TIME_100NS_FIELD_NUMBER: _ClassVar[int]
    LOGON_SERVER_FIELD_NUMBER: _ClassVar[int]
    DNS_DOMAIN_NAME_FIELD_NUMBER: _ClassVar[int]
    UPN_FIELD_NUMBER: _ClassVar[int]
    USER_FLAGS_FIELD_NUMBER: _ClassVar[int]
    logon_id_low: int
    logon_id_high: int
    user_name: str
    auth_domain: str
    logon_type: int
    logon_type_name: str
    session_id: int
    logon_time_100ns: int
    logoff_time_100ns: int
    logon_server: str
    dns_domain_name: str
    upn: str
    user_flags: int
    def __init__(self, logon_id_low: _Optional[int] = ..., logon_id_high: _Optional[int] = ..., user_name: _Optional[str] = ..., auth_domain: _Optional[str] = ..., logon_type: _Optional[int] = ..., logon_type_name: _Optional[str] = ..., session_id: _Optional[int] = ..., logon_time_100ns: _Optional[int] = ..., logoff_time_100ns: _Optional[int] = ..., logon_server: _Optional[str] = ..., dns_domain_name: _Optional[str] = ..., upn: _Optional[str] = ..., user_flags: _Optional[int] = ...) -> None: ...

class TokenViewRequest(_message.Message):
    __slots__ = ("pid", "tid", "include_groups", "include_privileges", "include_security_attributes", "include_logon_session")
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_GROUPS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_PRIVILEGES_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_SECURITY_ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_LOGON_SESSION_FIELD_NUMBER: _ClassVar[int]
    pid: int
    tid: int
    include_groups: bool
    include_privileges: bool
    include_security_attributes: bool
    include_logon_session: bool
    def __init__(self, pid: _Optional[int] = ..., tid: _Optional[int] = ..., include_groups: _Optional[bool] = ..., include_privileges: _Optional[bool] = ..., include_security_attributes: _Optional[bool] = ..., include_logon_session: _Optional[bool] = ...) -> None: ...

class TokenViewResponse(_message.Message):
    __slots__ = ("status", "core", "groups", "privileges", "capabilities", "security_attributes_raw", "logon_session", "token_source", "thread_impersonating")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CORE_FIELD_NUMBER: _ClassVar[int]
    GROUPS_FIELD_NUMBER: _ClassVar[int]
    PRIVILEGES_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    SECURITY_ATTRIBUTES_RAW_FIELD_NUMBER: _ClassVar[int]
    LOGON_SESSION_FIELD_NUMBER: _ClassVar[int]
    TOKEN_SOURCE_FIELD_NUMBER: _ClassVar[int]
    THREAD_IMPERSONATING_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    core: TokenCore
    groups: _containers.RepeatedCompositeFieldContainer[TokenGroup]
    privileges: _containers.RepeatedCompositeFieldContainer[TokenPrivilege]
    capabilities: _containers.RepeatedCompositeFieldContainer[TokenCapability]
    security_attributes_raw: bytes
    logon_session: LogonSessionInfo
    token_source: str
    thread_impersonating: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., core: _Optional[_Union[TokenCore, _Mapping]] = ..., groups: _Optional[_Iterable[_Union[TokenGroup, _Mapping]]] = ..., privileges: _Optional[_Iterable[_Union[TokenPrivilege, _Mapping]]] = ..., capabilities: _Optional[_Iterable[_Union[TokenCapability, _Mapping]]] = ..., security_attributes_raw: _Optional[bytes] = ..., logon_session: _Optional[_Union[LogonSessionInfo, _Mapping]] = ..., token_source: _Optional[str] = ..., thread_impersonating: _Optional[bool] = ...) -> None: ...

class AdjustPrivilegeRequest(_message.Message):
    __slots__ = ("pid", "tid", "privilege_name", "luid_low", "luid_high", "action")
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    PRIVILEGE_NAME_FIELD_NUMBER: _ClassVar[int]
    LUID_LOW_FIELD_NUMBER: _ClassVar[int]
    LUID_HIGH_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    pid: int
    tid: int
    privilege_name: str
    luid_low: int
    luid_high: int
    action: str
    def __init__(self, pid: _Optional[int] = ..., tid: _Optional[int] = ..., privilege_name: _Optional[str] = ..., luid_low: _Optional[int] = ..., luid_high: _Optional[int] = ..., action: _Optional[str] = ...) -> None: ...

class AdjustPrivilegeResponse(_message.Message):
    __slots__ = ("status", "previous_state", "new_state", "luid_low", "luid_high")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_STATE_FIELD_NUMBER: _ClassVar[int]
    NEW_STATE_FIELD_NUMBER: _ClassVar[int]
    LUID_LOW_FIELD_NUMBER: _ClassVar[int]
    LUID_HIGH_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    previous_state: str
    new_state: str
    luid_low: int
    luid_high: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., previous_state: _Optional[str] = ..., new_state: _Optional[str] = ..., luid_low: _Optional[int] = ..., luid_high: _Optional[int] = ...) -> None: ...

class SetIntegrityLevelRequest(_message.Message):
    __slots__ = ("pid", "tid", "integrity_rid", "integrity_name")
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    INTEGRITY_RID_FIELD_NUMBER: _ClassVar[int]
    INTEGRITY_NAME_FIELD_NUMBER: _ClassVar[int]
    pid: int
    tid: int
    integrity_rid: int
    integrity_name: str
    def __init__(self, pid: _Optional[int] = ..., tid: _Optional[int] = ..., integrity_rid: _Optional[int] = ..., integrity_name: _Optional[str] = ...) -> None: ...

class SetIntegrityLevelResponse(_message.Message):
    __slots__ = ("status", "previous_rid", "new_rid")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_RID_FIELD_NUMBER: _ClassVar[int]
    NEW_RID_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    previous_rid: int
    new_rid: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., previous_rid: _Optional[int] = ..., new_rid: _Optional[int] = ...) -> None: ...

class SetVirtualizationRequest(_message.Message):
    __slots__ = ("pid", "tid", "enable")
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    ENABLE_FIELD_NUMBER: _ClassVar[int]
    pid: int
    tid: int
    enable: bool
    def __init__(self, pid: _Optional[int] = ..., tid: _Optional[int] = ..., enable: _Optional[bool] = ...) -> None: ...

class SetVirtualizationResponse(_message.Message):
    __slots__ = ("status", "previous", "new_value")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_FIELD_NUMBER: _ClassVar[int]
    NEW_VALUE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    previous: bool
    new_value: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., previous: _Optional[bool] = ..., new_value: _Optional[bool] = ...) -> None: ...

class ImpersonateRequest(_message.Message):
    __slots__ = ("source_pid", "source_tid", "persist", "target_tid", "impersonation_level")
    SOURCE_PID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_TID_FIELD_NUMBER: _ClassVar[int]
    PERSIST_FIELD_NUMBER: _ClassVar[int]
    TARGET_TID_FIELD_NUMBER: _ClassVar[int]
    IMPERSONATION_LEVEL_FIELD_NUMBER: _ClassVar[int]
    source_pid: int
    source_tid: int
    persist: bool
    target_tid: int
    impersonation_level: str
    def __init__(self, source_pid: _Optional[int] = ..., source_tid: _Optional[int] = ..., persist: _Optional[bool] = ..., target_tid: _Optional[int] = ..., impersonation_level: _Optional[str] = ...) -> None: ...

class ImpersonateResponse(_message.Message):
    __slots__ = ("status", "impersonation_id", "agent_thread_id", "level_granted")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    IMPERSONATION_ID_FIELD_NUMBER: _ClassVar[int]
    AGENT_THREAD_ID_FIELD_NUMBER: _ClassVar[int]
    LEVEL_GRANTED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    impersonation_id: str
    agent_thread_id: int
    level_granted: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., impersonation_id: _Optional[str] = ..., agent_thread_id: _Optional[int] = ..., level_granted: _Optional[str] = ...) -> None: ...

class StopImpersonateRequest(_message.Message):
    __slots__ = ("impersonation_id",)
    IMPERSONATION_ID_FIELD_NUMBER: _ClassVar[int]
    impersonation_id: str
    def __init__(self, impersonation_id: _Optional[str] = ...) -> None: ...

class DaclAce(_message.Message):
    __slots__ = ("sid", "access_mask", "type", "flags")
    SID_FIELD_NUMBER: _ClassVar[int]
    ACCESS_MASK_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    sid: str
    access_mask: int
    type: str
    flags: int
    def __init__(self, sid: _Optional[str] = ..., access_mask: _Optional[int] = ..., type: _Optional[str] = ..., flags: _Optional[int] = ...) -> None: ...

class ModifyDefaultDaclRequest(_message.Message):
    __slots__ = ("pid", "tid", "aces", "replace")
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    ACES_FIELD_NUMBER: _ClassVar[int]
    REPLACE_FIELD_NUMBER: _ClassVar[int]
    pid: int
    tid: int
    aces: _containers.RepeatedCompositeFieldContainer[DaclAce]
    replace: bool
    def __init__(self, pid: _Optional[int] = ..., tid: _Optional[int] = ..., aces: _Optional[_Iterable[_Union[DaclAce, _Mapping]]] = ..., replace: _Optional[bool] = ...) -> None: ...

class ModifyDefaultDaclResponse(_message.Message):
    __slots__ = ("status", "ace_count_before", "ace_count_after")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ACE_COUNT_BEFORE_FIELD_NUMBER: _ClassVar[int]
    ACE_COUNT_AFTER_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    ace_count_before: int
    ace_count_after: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., ace_count_before: _Optional[int] = ..., ace_count_after: _Optional[int] = ...) -> None: ...

class LookupRow(_message.Message):
    __slots__ = ("input", "sid", "name", "domain", "use", "well_known")
    INPUT_FIELD_NUMBER: _ClassVar[int]
    SID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    USE_FIELD_NUMBER: _ClassVar[int]
    WELL_KNOWN_FIELD_NUMBER: _ClassVar[int]
    input: str
    sid: str
    name: str
    domain: str
    use: str
    well_known: bool
    def __init__(self, input: _Optional[str] = ..., sid: _Optional[str] = ..., name: _Optional[str] = ..., domain: _Optional[str] = ..., use: _Optional[str] = ..., well_known: _Optional[bool] = ...) -> None: ...

class LookupSidRequest(_message.Message):
    __slots__ = ("sids", "names")
    SIDS_FIELD_NUMBER: _ClassVar[int]
    NAMES_FIELD_NUMBER: _ClassVar[int]
    sids: _containers.RepeatedScalarFieldContainer[str]
    names: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, sids: _Optional[_Iterable[str]] = ..., names: _Optional[_Iterable[str]] = ...) -> None: ...

class LookupSidResponse(_message.Message):
    __slots__ = ("status", "rows")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    rows: _containers.RepeatedCompositeFieldContainer[LookupRow]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., rows: _Optional[_Iterable[_Union[LookupRow, _Mapping]]] = ...) -> None: ...

class LogonSessionsRequest(_message.Message):
    __slots__ = ("include_dns_names",)
    INCLUDE_DNS_NAMES_FIELD_NUMBER: _ClassVar[int]
    include_dns_names: bool
    def __init__(self, include_dns_names: _Optional[bool] = ...) -> None: ...

class LogonSessionsResponse(_message.Message):
    __slots__ = ("status", "sessions")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SESSIONS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    sessions: _containers.RepeatedCompositeFieldContainer[LogonSessionInfo]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., sessions: _Optional[_Iterable[_Union[LogonSessionInfo, _Mapping]]] = ...) -> None: ...

class MitDep(_message.Message):
    __slots__ = ("enable", "atl_thunk_emulation_disable", "permanent")
    ENABLE_FIELD_NUMBER: _ClassVar[int]
    ATL_THUNK_EMULATION_DISABLE_FIELD_NUMBER: _ClassVar[int]
    PERMANENT_FIELD_NUMBER: _ClassVar[int]
    enable: bool
    atl_thunk_emulation_disable: bool
    permanent: bool
    def __init__(self, enable: _Optional[bool] = ..., atl_thunk_emulation_disable: _Optional[bool] = ..., permanent: _Optional[bool] = ...) -> None: ...

class MitAslr(_message.Message):
    __slots__ = ("bottom_up", "force_relocate", "high_entropy", "disallow_stripped_images", "bottom_up_high_entropy", "high_address_space_override")
    BOTTOM_UP_FIELD_NUMBER: _ClassVar[int]
    FORCE_RELOCATE_FIELD_NUMBER: _ClassVar[int]
    HIGH_ENTROPY_FIELD_NUMBER: _ClassVar[int]
    DISALLOW_STRIPPED_IMAGES_FIELD_NUMBER: _ClassVar[int]
    BOTTOM_UP_HIGH_ENTROPY_FIELD_NUMBER: _ClassVar[int]
    HIGH_ADDRESS_SPACE_OVERRIDE_FIELD_NUMBER: _ClassVar[int]
    bottom_up: bool
    force_relocate: bool
    high_entropy: bool
    disallow_stripped_images: bool
    bottom_up_high_entropy: bool
    high_address_space_override: bool
    def __init__(self, bottom_up: _Optional[bool] = ..., force_relocate: _Optional[bool] = ..., high_entropy: _Optional[bool] = ..., disallow_stripped_images: _Optional[bool] = ..., bottom_up_high_entropy: _Optional[bool] = ..., high_address_space_override: _Optional[bool] = ...) -> None: ...

class MitCfg(_message.Message):
    __slots__ = ("enable", "strict_mode", "suppress_exports", "export_dynamic_invalidation")
    ENABLE_FIELD_NUMBER: _ClassVar[int]
    STRICT_MODE_FIELD_NUMBER: _ClassVar[int]
    SUPPRESS_EXPORTS_FIELD_NUMBER: _ClassVar[int]
    EXPORT_DYNAMIC_INVALIDATION_FIELD_NUMBER: _ClassVar[int]
    enable: bool
    strict_mode: bool
    suppress_exports: bool
    export_dynamic_invalidation: bool
    def __init__(self, enable: _Optional[bool] = ..., strict_mode: _Optional[bool] = ..., suppress_exports: _Optional[bool] = ..., export_dynamic_invalidation: _Optional[bool] = ...) -> None: ...

class MitSysCall(_message.Message):
    __slots__ = ("disable", "allow_win32k_system_calls")
    DISABLE_FIELD_NUMBER: _ClassVar[int]
    ALLOW_WIN32K_SYSTEM_CALLS_FIELD_NUMBER: _ClassVar[int]
    disable: bool
    allow_win32k_system_calls: bool
    def __init__(self, disable: _Optional[bool] = ..., allow_win32k_system_calls: _Optional[bool] = ...) -> None: ...

class MitDynCode(_message.Message):
    __slots__ = ("prohibit", "allow_thread_opt_out", "allow_remote_downgrade", "audit", "audit_allow_thread_opt_out", "audit_allow_remote_downgrade")
    PROHIBIT_FIELD_NUMBER: _ClassVar[int]
    ALLOW_THREAD_OPT_OUT_FIELD_NUMBER: _ClassVar[int]
    ALLOW_REMOTE_DOWNGRADE_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    AUDIT_ALLOW_THREAD_OPT_OUT_FIELD_NUMBER: _ClassVar[int]
    AUDIT_ALLOW_REMOTE_DOWNGRADE_FIELD_NUMBER: _ClassVar[int]
    prohibit: bool
    allow_thread_opt_out: bool
    allow_remote_downgrade: bool
    audit: bool
    audit_allow_thread_opt_out: bool
    audit_allow_remote_downgrade: bool
    def __init__(self, prohibit: _Optional[bool] = ..., allow_thread_opt_out: _Optional[bool] = ..., allow_remote_downgrade: _Optional[bool] = ..., audit: _Optional[bool] = ..., audit_allow_thread_opt_out: _Optional[bool] = ..., audit_allow_remote_downgrade: _Optional[bool] = ...) -> None: ...

class MitBinSig(_message.Message):
    __slots__ = ("micro_signed_only", "store_signed_only", "mitigation_opt_in", "mitigation_audit_mask", "oem_signed_loosened_to_wintcb")
    MICRO_SIGNED_ONLY_FIELD_NUMBER: _ClassVar[int]
    STORE_SIGNED_ONLY_FIELD_NUMBER: _ClassVar[int]
    MITIGATION_OPT_IN_FIELD_NUMBER: _ClassVar[int]
    MITIGATION_AUDIT_MASK_FIELD_NUMBER: _ClassVar[int]
    OEM_SIGNED_LOOSENED_TO_WINTCB_FIELD_NUMBER: _ClassVar[int]
    micro_signed_only: bool
    store_signed_only: bool
    mitigation_opt_in: bool
    mitigation_audit_mask: int
    oem_signed_loosened_to_wintcb: bool
    def __init__(self, micro_signed_only: _Optional[bool] = ..., store_signed_only: _Optional[bool] = ..., mitigation_opt_in: _Optional[bool] = ..., mitigation_audit_mask: _Optional[int] = ..., oem_signed_loosened_to_wintcb: _Optional[bool] = ...) -> None: ...

class MitFont(_message.Message):
    __slots__ = ("disable_non_system_fonts", "audit")
    DISABLE_NON_SYSTEM_FONTS_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    disable_non_system_fonts: bool
    audit: bool
    def __init__(self, disable_non_system_fonts: _Optional[bool] = ..., audit: _Optional[bool] = ...) -> None: ...

class MitImageLoad(_message.Message):
    __slots__ = ("no_remote_images", "no_low_mandatory_label_images", "prefer_system32", "audit_no_remote_images", "audit_no_low_mandatory_label_images", "audit_prefer_system32")
    NO_REMOTE_IMAGES_FIELD_NUMBER: _ClassVar[int]
    NO_LOW_MANDATORY_LABEL_IMAGES_FIELD_NUMBER: _ClassVar[int]
    PREFER_SYSTEM32_FIELD_NUMBER: _ClassVar[int]
    AUDIT_NO_REMOTE_IMAGES_FIELD_NUMBER: _ClassVar[int]
    AUDIT_NO_LOW_MANDATORY_LABEL_IMAGES_FIELD_NUMBER: _ClassVar[int]
    AUDIT_PREFER_SYSTEM32_FIELD_NUMBER: _ClassVar[int]
    no_remote_images: bool
    no_low_mandatory_label_images: bool
    prefer_system32: bool
    audit_no_remote_images: bool
    audit_no_low_mandatory_label_images: bool
    audit_prefer_system32: bool
    def __init__(self, no_remote_images: _Optional[bool] = ..., no_low_mandatory_label_images: _Optional[bool] = ..., prefer_system32: _Optional[bool] = ..., audit_no_remote_images: _Optional[bool] = ..., audit_no_low_mandatory_label_images: _Optional[bool] = ..., audit_prefer_system32: _Optional[bool] = ...) -> None: ...

class MitShadowStack(_message.Message):
    __slots__ = ("enabled", "audit", "strict_mode", "set_context_ip_validation", "set_context_ip_validation_relaxed_mode", "block_non_cet_binaries", "block_non_cet_binaries_non_ehcont", "cet_dynamic_apis_out_of_proc_only", "audit_set_context_ip_validation", "audit_block_non_cet_binaries")
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    STRICT_MODE_FIELD_NUMBER: _ClassVar[int]
    SET_CONTEXT_IP_VALIDATION_FIELD_NUMBER: _ClassVar[int]
    SET_CONTEXT_IP_VALIDATION_RELAXED_MODE_FIELD_NUMBER: _ClassVar[int]
    BLOCK_NON_CET_BINARIES_FIELD_NUMBER: _ClassVar[int]
    BLOCK_NON_CET_BINARIES_NON_EHCONT_FIELD_NUMBER: _ClassVar[int]
    CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY_FIELD_NUMBER: _ClassVar[int]
    AUDIT_SET_CONTEXT_IP_VALIDATION_FIELD_NUMBER: _ClassVar[int]
    AUDIT_BLOCK_NON_CET_BINARIES_FIELD_NUMBER: _ClassVar[int]
    enabled: bool
    audit: bool
    strict_mode: bool
    set_context_ip_validation: bool
    set_context_ip_validation_relaxed_mode: bool
    block_non_cet_binaries: bool
    block_non_cet_binaries_non_ehcont: bool
    cet_dynamic_apis_out_of_proc_only: bool
    audit_set_context_ip_validation: bool
    audit_block_non_cet_binaries: bool
    def __init__(self, enabled: _Optional[bool] = ..., audit: _Optional[bool] = ..., strict_mode: _Optional[bool] = ..., set_context_ip_validation: _Optional[bool] = ..., set_context_ip_validation_relaxed_mode: _Optional[bool] = ..., block_non_cet_binaries: _Optional[bool] = ..., block_non_cet_binaries_non_ehcont: _Optional[bool] = ..., cet_dynamic_apis_out_of_proc_only: _Optional[bool] = ..., audit_set_context_ip_validation: _Optional[bool] = ..., audit_block_non_cet_binaries: _Optional[bool] = ...) -> None: ...

class MitPayload(_message.Message):
    __slots__ = ("enable_export_address_filter", "enable_export_address_filter_plus", "audit_export_address_filter", "audit_export_address_filter_plus", "enable_import_address_filter", "audit_import_address_filter", "enable_rop_stack_pivot", "audit_rop_stack_pivot", "enable_rop_caller_check", "audit_rop_caller_check", "enable_rop_sim_exec", "audit_rop_sim_exec")
    ENABLE_EXPORT_ADDRESS_FILTER_FIELD_NUMBER: _ClassVar[int]
    ENABLE_EXPORT_ADDRESS_FILTER_PLUS_FIELD_NUMBER: _ClassVar[int]
    AUDIT_EXPORT_ADDRESS_FILTER_FIELD_NUMBER: _ClassVar[int]
    AUDIT_EXPORT_ADDRESS_FILTER_PLUS_FIELD_NUMBER: _ClassVar[int]
    ENABLE_IMPORT_ADDRESS_FILTER_FIELD_NUMBER: _ClassVar[int]
    AUDIT_IMPORT_ADDRESS_FILTER_FIELD_NUMBER: _ClassVar[int]
    ENABLE_ROP_STACK_PIVOT_FIELD_NUMBER: _ClassVar[int]
    AUDIT_ROP_STACK_PIVOT_FIELD_NUMBER: _ClassVar[int]
    ENABLE_ROP_CALLER_CHECK_FIELD_NUMBER: _ClassVar[int]
    AUDIT_ROP_CALLER_CHECK_FIELD_NUMBER: _ClassVar[int]
    ENABLE_ROP_SIM_EXEC_FIELD_NUMBER: _ClassVar[int]
    AUDIT_ROP_SIM_EXEC_FIELD_NUMBER: _ClassVar[int]
    enable_export_address_filter: bool
    enable_export_address_filter_plus: bool
    audit_export_address_filter: bool
    audit_export_address_filter_plus: bool
    enable_import_address_filter: bool
    audit_import_address_filter: bool
    enable_rop_stack_pivot: bool
    audit_rop_stack_pivot: bool
    enable_rop_caller_check: bool
    audit_rop_caller_check: bool
    enable_rop_sim_exec: bool
    audit_rop_sim_exec: bool
    def __init__(self, enable_export_address_filter: _Optional[bool] = ..., enable_export_address_filter_plus: _Optional[bool] = ..., audit_export_address_filter: _Optional[bool] = ..., audit_export_address_filter_plus: _Optional[bool] = ..., enable_import_address_filter: _Optional[bool] = ..., audit_import_address_filter: _Optional[bool] = ..., enable_rop_stack_pivot: _Optional[bool] = ..., audit_rop_stack_pivot: _Optional[bool] = ..., enable_rop_caller_check: _Optional[bool] = ..., audit_rop_caller_check: _Optional[bool] = ..., enable_rop_sim_exec: _Optional[bool] = ..., audit_rop_sim_exec: _Optional[bool] = ...) -> None: ...

class MitSideChannel(_message.Message):
    __slots__ = ("smt_branch_target_isolation", "isolate_security_domain", "disable_page_combine", "speculative_store_bypass_disable")
    SMT_BRANCH_TARGET_ISOLATION_FIELD_NUMBER: _ClassVar[int]
    ISOLATE_SECURITY_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    DISABLE_PAGE_COMBINE_FIELD_NUMBER: _ClassVar[int]
    SPECULATIVE_STORE_BYPASS_DISABLE_FIELD_NUMBER: _ClassVar[int]
    smt_branch_target_isolation: bool
    isolate_security_domain: bool
    disable_page_combine: bool
    speculative_store_bypass_disable: bool
    def __init__(self, smt_branch_target_isolation: _Optional[bool] = ..., isolate_security_domain: _Optional[bool] = ..., disable_page_combine: _Optional[bool] = ..., speculative_store_bypass_disable: _Optional[bool] = ...) -> None: ...

class MitRedirectionTrust(_message.Message):
    __slots__ = ("enforce", "audit")
    ENFORCE_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    enforce: bool
    audit: bool
    def __init__(self, enforce: _Optional[bool] = ..., audit: _Optional[bool] = ...) -> None: ...

class MitigationRow(_message.Message):
    __slots__ = ("pid", "create_time_100ns", "error", "cache_hit", "dep", "aslr", "cfg", "strict_handle_check", "syscall", "extension_points_disabled", "dynamic_code", "binary_signature", "font_disable", "image_load", "user_shadow_stack", "payload_restriction", "side_channel", "redirection_trust")
    PID_FIELD_NUMBER: _ClassVar[int]
    CREATE_TIME_100NS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    CACHE_HIT_FIELD_NUMBER: _ClassVar[int]
    DEP_FIELD_NUMBER: _ClassVar[int]
    ASLR_FIELD_NUMBER: _ClassVar[int]
    CFG_FIELD_NUMBER: _ClassVar[int]
    STRICT_HANDLE_CHECK_FIELD_NUMBER: _ClassVar[int]
    SYSCALL_FIELD_NUMBER: _ClassVar[int]
    EXTENSION_POINTS_DISABLED_FIELD_NUMBER: _ClassVar[int]
    DYNAMIC_CODE_FIELD_NUMBER: _ClassVar[int]
    BINARY_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    FONT_DISABLE_FIELD_NUMBER: _ClassVar[int]
    IMAGE_LOAD_FIELD_NUMBER: _ClassVar[int]
    USER_SHADOW_STACK_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_RESTRICTION_FIELD_NUMBER: _ClassVar[int]
    SIDE_CHANNEL_FIELD_NUMBER: _ClassVar[int]
    REDIRECTION_TRUST_FIELD_NUMBER: _ClassVar[int]
    pid: int
    create_time_100ns: int
    error: str
    cache_hit: bool
    dep: MitDep
    aslr: MitAslr
    cfg: MitCfg
    strict_handle_check: bool
    syscall: MitSysCall
    extension_points_disabled: bool
    dynamic_code: MitDynCode
    binary_signature: MitBinSig
    font_disable: MitFont
    image_load: MitImageLoad
    user_shadow_stack: MitShadowStack
    payload_restriction: MitPayload
    side_channel: MitSideChannel
    redirection_trust: MitRedirectionTrust
    def __init__(self, pid: _Optional[int] = ..., create_time_100ns: _Optional[int] = ..., error: _Optional[str] = ..., cache_hit: _Optional[bool] = ..., dep: _Optional[_Union[MitDep, _Mapping]] = ..., aslr: _Optional[_Union[MitAslr, _Mapping]] = ..., cfg: _Optional[_Union[MitCfg, _Mapping]] = ..., strict_handle_check: _Optional[bool] = ..., syscall: _Optional[_Union[MitSysCall, _Mapping]] = ..., extension_points_disabled: _Optional[bool] = ..., dynamic_code: _Optional[_Union[MitDynCode, _Mapping]] = ..., binary_signature: _Optional[_Union[MitBinSig, _Mapping]] = ..., font_disable: _Optional[_Union[MitFont, _Mapping]] = ..., image_load: _Optional[_Union[MitImageLoad, _Mapping]] = ..., user_shadow_stack: _Optional[_Union[MitShadowStack, _Mapping]] = ..., payload_restriction: _Optional[_Union[MitPayload, _Mapping]] = ..., side_channel: _Optional[_Union[MitSideChannel, _Mapping]] = ..., redirection_trust: _Optional[_Union[MitRedirectionTrust, _Mapping]] = ...) -> None: ...

class GetMitigationPolicyRequest(_message.Message):
    __slots__ = ("pids", "force_recheck")
    PIDS_FIELD_NUMBER: _ClassVar[int]
    FORCE_RECHECK_FIELD_NUMBER: _ClassVar[int]
    pids: _containers.RepeatedScalarFieldContainer[int]
    force_recheck: bool
    def __init__(self, pids: _Optional[_Iterable[int]] = ..., force_recheck: _Optional[bool] = ...) -> None: ...

class GetMitigationPolicyResponse(_message.Message):
    __slots__ = ("status", "rows", "cache_hits", "probed")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    CACHE_HITS_FIELD_NUMBER: _ClassVar[int]
    PROBED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    rows: _containers.RepeatedCompositeFieldContainer[MitigationRow]
    cache_hits: int
    probed: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., rows: _Optional[_Iterable[_Union[MitigationRow, _Mapping]]] = ..., cache_hits: _Optional[int] = ..., probed: _Optional[int] = ...) -> None: ...

class NetConnEntry(_message.Message):
    __slots__ = ("proto", "family", "pid", "process", "state", "local", "remote", "create_time_ms", "offload", "scope_id_local", "scope_id_remote", "service_tag", "remote_host", "owning_module_names")
    PROTO_FIELD_NUMBER: _ClassVar[int]
    FAMILY_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    LOCAL_FIELD_NUMBER: _ClassVar[int]
    REMOTE_FIELD_NUMBER: _ClassVar[int]
    CREATE_TIME_MS_FIELD_NUMBER: _ClassVar[int]
    OFFLOAD_FIELD_NUMBER: _ClassVar[int]
    SCOPE_ID_LOCAL_FIELD_NUMBER: _ClassVar[int]
    SCOPE_ID_REMOTE_FIELD_NUMBER: _ClassVar[int]
    SERVICE_TAG_FIELD_NUMBER: _ClassVar[int]
    REMOTE_HOST_FIELD_NUMBER: _ClassVar[int]
    OWNING_MODULE_NAMES_FIELD_NUMBER: _ClassVar[int]
    proto: str
    family: str
    pid: int
    process: str
    state: str
    local: str
    remote: str
    create_time_ms: int
    offload: str
    scope_id_local: int
    scope_id_remote: int
    service_tag: str
    remote_host: str
    owning_module_names: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, proto: _Optional[str] = ..., family: _Optional[str] = ..., pid: _Optional[int] = ..., process: _Optional[str] = ..., state: _Optional[str] = ..., local: _Optional[str] = ..., remote: _Optional[str] = ..., create_time_ms: _Optional[int] = ..., offload: _Optional[str] = ..., scope_id_local: _Optional[int] = ..., scope_id_remote: _Optional[int] = ..., service_tag: _Optional[str] = ..., remote_host: _Optional[str] = ..., owning_module_names: _Optional[_Iterable[str]] = ...) -> None: ...

class NetListRequest(_message.Message):
    __slots__ = ("families", "protos", "states", "pid", "include_loopback", "module_resolve", "include_services", "resolve_hostnames", "limit")
    FAMILIES_FIELD_NUMBER: _ClassVar[int]
    PROTOS_FIELD_NUMBER: _ClassVar[int]
    STATES_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_LOOPBACK_FIELD_NUMBER: _ClassVar[int]
    MODULE_RESOLVE_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_SERVICES_FIELD_NUMBER: _ClassVar[int]
    RESOLVE_HOSTNAMES_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    families: _containers.RepeatedScalarFieldContainer[str]
    protos: _containers.RepeatedScalarFieldContainer[str]
    states: _containers.RepeatedScalarFieldContainer[str]
    pid: int
    include_loopback: bool
    module_resolve: bool
    include_services: bool
    resolve_hostnames: bool
    limit: int
    def __init__(self, families: _Optional[_Iterable[str]] = ..., protos: _Optional[_Iterable[str]] = ..., states: _Optional[_Iterable[str]] = ..., pid: _Optional[int] = ..., include_loopback: _Optional[bool] = ..., module_resolve: _Optional[bool] = ..., include_services: _Optional[bool] = ..., resolve_hostnames: _Optional[bool] = ..., limit: _Optional[int] = ...) -> None: ...

class NetListResponse(_message.Message):
    __slots__ = ("status", "items", "total", "truncated", "dns_cache_hits", "dns_cache_misses", "dns_cache_size")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    DNS_CACHE_HITS_FIELD_NUMBER: _ClassVar[int]
    DNS_CACHE_MISSES_FIELD_NUMBER: _ClassVar[int]
    DNS_CACHE_SIZE_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    items: _containers.RepeatedCompositeFieldContainer[NetConnEntry]
    total: int
    truncated: bool
    dns_cache_hits: int
    dns_cache_misses: int
    dns_cache_size: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., items: _Optional[_Iterable[_Union[NetConnEntry, _Mapping]]] = ..., total: _Optional[int] = ..., truncated: _Optional[bool] = ..., dns_cache_hits: _Optional[int] = ..., dns_cache_misses: _Optional[int] = ..., dns_cache_size: _Optional[int] = ...) -> None: ...

class NetInterfaceEntry(_message.Message):
    __slots__ = ("name", "friendly_name", "description", "if_index", "if_type", "oper_status", "speed_bps", "unicast", "gateways", "dns_servers", "mac")
    NAME_FIELD_NUMBER: _ClassVar[int]
    FRIENDLY_NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    IF_INDEX_FIELD_NUMBER: _ClassVar[int]
    IF_TYPE_FIELD_NUMBER: _ClassVar[int]
    OPER_STATUS_FIELD_NUMBER: _ClassVar[int]
    SPEED_BPS_FIELD_NUMBER: _ClassVar[int]
    UNICAST_FIELD_NUMBER: _ClassVar[int]
    GATEWAYS_FIELD_NUMBER: _ClassVar[int]
    DNS_SERVERS_FIELD_NUMBER: _ClassVar[int]
    MAC_FIELD_NUMBER: _ClassVar[int]
    name: str
    friendly_name: str
    description: str
    if_index: int
    if_type: int
    oper_status: str
    speed_bps: int
    unicast: _containers.RepeatedScalarFieldContainer[str]
    gateways: _containers.RepeatedScalarFieldContainer[str]
    dns_servers: _containers.RepeatedScalarFieldContainer[str]
    mac: str
    def __init__(self, name: _Optional[str] = ..., friendly_name: _Optional[str] = ..., description: _Optional[str] = ..., if_index: _Optional[int] = ..., if_type: _Optional[int] = ..., oper_status: _Optional[str] = ..., speed_bps: _Optional[int] = ..., unicast: _Optional[_Iterable[str]] = ..., gateways: _Optional[_Iterable[str]] = ..., dns_servers: _Optional[_Iterable[str]] = ..., mac: _Optional[str] = ...) -> None: ...

class NetInterfacesRequest(_message.Message):
    __slots__ = ("include_down",)
    INCLUDE_DOWN_FIELD_NUMBER: _ClassVar[int]
    include_down: bool
    def __init__(self, include_down: _Optional[bool] = ...) -> None: ...

class NetInterfacesResponse(_message.Message):
    __slots__ = ("status", "items")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    items: _containers.RepeatedCompositeFieldContainer[NetInterfaceEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., items: _Optional[_Iterable[_Union[NetInterfaceEntry, _Mapping]]] = ...) -> None: ...

class NetStatsRequest(_message.Message):
    __slots__ = ("families", "protos")
    FAMILIES_FIELD_NUMBER: _ClassVar[int]
    PROTOS_FIELD_NUMBER: _ClassVar[int]
    families: _containers.RepeatedScalarFieldContainer[str]
    protos: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, families: _Optional[_Iterable[str]] = ..., protos: _Optional[_Iterable[str]] = ...) -> None: ...

class NetStatsCounter(_message.Message):
    __slots__ = ("name", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: int
    def __init__(self, name: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...

class NetStatsResponse(_message.Message):
    __slots__ = ("status", "counters")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    COUNTERS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    counters: _containers.RepeatedCompositeFieldContainer[NetStatsCounter]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., counters: _Optional[_Iterable[_Union[NetStatsCounter, _Mapping]]] = ...) -> None: ...

class NetKillRequest(_message.Message):
    __slots__ = ("local", "remote", "state_hint")
    LOCAL_FIELD_NUMBER: _ClassVar[int]
    REMOTE_FIELD_NUMBER: _ClassVar[int]
    STATE_HINT_FIELD_NUMBER: _ClassVar[int]
    local: str
    remote: str
    state_hint: str
    def __init__(self, local: _Optional[str] = ..., remote: _Optional[str] = ..., state_hint: _Optional[str] = ...) -> None: ...

class NetKillResponse(_message.Message):
    __slots__ = ("status", "killed")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    KILLED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    killed: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., killed: _Optional[bool] = ...) -> None: ...

class SvcTriggerAction(_message.Message):
    __slots__ = ("type", "subtype", "action", "data_items")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SUBTYPE_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    DATA_ITEMS_FIELD_NUMBER: _ClassVar[int]
    type: str
    subtype: str
    action: str
    data_items: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, type: _Optional[str] = ..., subtype: _Optional[str] = ..., action: _Optional[str] = ..., data_items: _Optional[_Iterable[str]] = ...) -> None: ...

class SvcFailureAction(_message.Message):
    __slots__ = ("action", "delay_ms", "reboot_message", "run_command")
    ACTION_FIELD_NUMBER: _ClassVar[int]
    DELAY_MS_FIELD_NUMBER: _ClassVar[int]
    REBOOT_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RUN_COMMAND_FIELD_NUMBER: _ClassVar[int]
    action: str
    delay_ms: int
    reboot_message: str
    run_command: str
    def __init__(self, action: _Optional[str] = ..., delay_ms: _Optional[int] = ..., reboot_message: _Optional[str] = ..., run_command: _Optional[str] = ...) -> None: ...

class SvcEntry(_message.Message):
    __slots__ = ("name", "display_name", "state", "start_type", "service_type", "pid", "image_path", "description", "service_sid_type", "service_sid", "launch_protected_level", "delayed_auto_start", "logon_account", "dependencies", "controls_accepted", "triggers", "failure_actions", "signer", "signing_level", "is_signed", "catalog", "signer_cache_hit", "signer_error", "module_base", "module_size", "module_timestamp", "warnings", "kind")
    NAME_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    START_TYPE_FIELD_NUMBER: _ClassVar[int]
    SERVICE_TYPE_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    IMAGE_PATH_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    SERVICE_SID_TYPE_FIELD_NUMBER: _ClassVar[int]
    SERVICE_SID_FIELD_NUMBER: _ClassVar[int]
    LAUNCH_PROTECTED_LEVEL_FIELD_NUMBER: _ClassVar[int]
    DELAYED_AUTO_START_FIELD_NUMBER: _ClassVar[int]
    LOGON_ACCOUNT_FIELD_NUMBER: _ClassVar[int]
    DEPENDENCIES_FIELD_NUMBER: _ClassVar[int]
    CONTROLS_ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    TRIGGERS_FIELD_NUMBER: _ClassVar[int]
    FAILURE_ACTIONS_FIELD_NUMBER: _ClassVar[int]
    SIGNER_FIELD_NUMBER: _ClassVar[int]
    SIGNING_LEVEL_FIELD_NUMBER: _ClassVar[int]
    IS_SIGNED_FIELD_NUMBER: _ClassVar[int]
    CATALOG_FIELD_NUMBER: _ClassVar[int]
    SIGNER_CACHE_HIT_FIELD_NUMBER: _ClassVar[int]
    SIGNER_ERROR_FIELD_NUMBER: _ClassVar[int]
    MODULE_BASE_FIELD_NUMBER: _ClassVar[int]
    MODULE_SIZE_FIELD_NUMBER: _ClassVar[int]
    MODULE_TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    name: str
    display_name: str
    state: str
    start_type: str
    service_type: str
    pid: int
    image_path: str
    description: str
    service_sid_type: str
    service_sid: str
    launch_protected_level: str
    delayed_auto_start: bool
    logon_account: str
    dependencies: _containers.RepeatedScalarFieldContainer[str]
    controls_accepted: _containers.RepeatedScalarFieldContainer[str]
    triggers: _containers.RepeatedCompositeFieldContainer[SvcTriggerAction]
    failure_actions: _containers.RepeatedCompositeFieldContainer[SvcFailureAction]
    signer: str
    signing_level: str
    is_signed: bool
    catalog: bool
    signer_cache_hit: bool
    signer_error: str
    module_base: int
    module_size: int
    module_timestamp: int
    warnings: str
    kind: str
    def __init__(self, name: _Optional[str] = ..., display_name: _Optional[str] = ..., state: _Optional[str] = ..., start_type: _Optional[str] = ..., service_type: _Optional[str] = ..., pid: _Optional[int] = ..., image_path: _Optional[str] = ..., description: _Optional[str] = ..., service_sid_type: _Optional[str] = ..., service_sid: _Optional[str] = ..., launch_protected_level: _Optional[str] = ..., delayed_auto_start: _Optional[bool] = ..., logon_account: _Optional[str] = ..., dependencies: _Optional[_Iterable[str]] = ..., controls_accepted: _Optional[_Iterable[str]] = ..., triggers: _Optional[_Iterable[_Union[SvcTriggerAction, _Mapping]]] = ..., failure_actions: _Optional[_Iterable[_Union[SvcFailureAction, _Mapping]]] = ..., signer: _Optional[str] = ..., signing_level: _Optional[str] = ..., is_signed: _Optional[bool] = ..., catalog: _Optional[bool] = ..., signer_cache_hit: _Optional[bool] = ..., signer_error: _Optional[str] = ..., module_base: _Optional[int] = ..., module_size: _Optional[int] = ..., module_timestamp: _Optional[int] = ..., warnings: _Optional[str] = ..., kind: _Optional[str] = ...) -> None: ...

class SvcListRequest(_message.Message):
    __slots__ = ("service_types", "start_types", "states", "name_contains", "include_driver_base", "verify_signatures", "limit")
    SERVICE_TYPES_FIELD_NUMBER: _ClassVar[int]
    START_TYPES_FIELD_NUMBER: _ClassVar[int]
    STATES_FIELD_NUMBER: _ClassVar[int]
    NAME_CONTAINS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_DRIVER_BASE_FIELD_NUMBER: _ClassVar[int]
    VERIFY_SIGNATURES_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    service_types: _containers.RepeatedScalarFieldContainer[str]
    start_types: _containers.RepeatedScalarFieldContainer[str]
    states: _containers.RepeatedScalarFieldContainer[str]
    name_contains: str
    include_driver_base: bool
    verify_signatures: bool
    limit: int
    def __init__(self, service_types: _Optional[_Iterable[str]] = ..., start_types: _Optional[_Iterable[str]] = ..., states: _Optional[_Iterable[str]] = ..., name_contains: _Optional[str] = ..., include_driver_base: _Optional[bool] = ..., verify_signatures: _Optional[bool] = ..., limit: _Optional[int] = ...) -> None: ...

class SvcListResponse(_message.Message):
    __slots__ = ("status", "items", "total", "truncated", "degraded_rows")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    DEGRADED_ROWS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    items: _containers.RepeatedCompositeFieldContainer[SvcEntry]
    total: int
    truncated: bool
    degraded_rows: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., items: _Optional[_Iterable[_Union[SvcEntry, _Mapping]]] = ..., total: _Optional[int] = ..., truncated: _Optional[bool] = ..., degraded_rows: _Optional[int] = ...) -> None: ...

class SvcGetRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class SvcGetResponse(_message.Message):
    __slots__ = ("status", "item")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ITEM_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    item: SvcEntry
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., item: _Optional[_Union[SvcEntry, _Mapping]] = ...) -> None: ...

class SvcDependenciesRequest(_message.Message):
    __slots__ = ("name", "reverse")
    NAME_FIELD_NUMBER: _ClassVar[int]
    REVERSE_FIELD_NUMBER: _ClassVar[int]
    name: str
    reverse: bool
    def __init__(self, name: _Optional[str] = ..., reverse: _Optional[bool] = ...) -> None: ...

class SvcDependenciesResponse(_message.Message):
    __slots__ = ("status", "items")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    items: _containers.RepeatedCompositeFieldContainer[SvcEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., items: _Optional[_Iterable[_Union[SvcEntry, _Mapping]]] = ...) -> None: ...

class SvcDriversRequest(_message.Message):
    __slots__ = ("include_unloaded", "verify_signatures")
    INCLUDE_UNLOADED_FIELD_NUMBER: _ClassVar[int]
    VERIFY_SIGNATURES_FIELD_NUMBER: _ClassVar[int]
    include_unloaded: bool
    verify_signatures: bool
    def __init__(self, include_unloaded: _Optional[bool] = ..., verify_signatures: _Optional[bool] = ...) -> None: ...

class SvcDriversResponse(_message.Message):
    __slots__ = ("status", "items")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    items: _containers.RepeatedCompositeFieldContainer[SvcEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., items: _Optional[_Iterable[_Union[SvcEntry, _Mapping]]] = ...) -> None: ...

class ThreadLastSyscall(_message.Message):
    __slots__ = ("number", "name", "status_hex")
    NUMBER_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    STATUS_HEX_FIELD_NUMBER: _ClassVar[int]
    number: int
    name: str
    status_hex: str
    def __init__(self, number: _Optional[int] = ..., name: _Optional[str] = ..., status_hex: _Optional[str] = ...) -> None: ...

class ThreadKernelStack(_message.Message):
    __slots__ = ("base_hex", "limit", "rsp", "excursion", "max_excursion")
    BASE_HEX_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    RSP_FIELD_NUMBER: _ClassVar[int]
    EXCURSION_FIELD_NUMBER: _ClassVar[int]
    MAX_EXCURSION_FIELD_NUMBER: _ClassVar[int]
    base_hex: int
    limit: int
    rsp: int
    excursion: int
    max_excursion: int
    def __init__(self, base_hex: _Optional[int] = ..., limit: _Optional[int] = ..., rsp: _Optional[int] = ..., excursion: _Optional[int] = ..., max_excursion: _Optional[int] = ...) -> None: ...

class ThreadWaitInfoRequest(_message.Message):
    __slots__ = ("tid",)
    TID_FIELD_NUMBER: _ClassVar[int]
    tid: int
    def __init__(self, tid: _Optional[int] = ...) -> None: ...

class ThreadWaitInfoResponse(_message.Message):
    __slots__ = ("status", "last_syscall", "kernel_stack", "wait_reason", "wait_mode", "wait_status", "thread_state", "error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LAST_SYSCALL_FIELD_NUMBER: _ClassVar[int]
    KERNEL_STACK_FIELD_NUMBER: _ClassVar[int]
    WAIT_REASON_FIELD_NUMBER: _ClassVar[int]
    WAIT_MODE_FIELD_NUMBER: _ClassVar[int]
    WAIT_STATUS_FIELD_NUMBER: _ClassVar[int]
    THREAD_STATE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    last_syscall: ThreadLastSyscall
    kernel_stack: ThreadKernelStack
    wait_reason: int
    wait_mode: int
    wait_status: int
    thread_state: int
    error: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., last_syscall: _Optional[_Union[ThreadLastSyscall, _Mapping]] = ..., kernel_stack: _Optional[_Union[ThreadKernelStack, _Mapping]] = ..., wait_reason: _Optional[int] = ..., wait_mode: _Optional[int] = ..., wait_status: _Optional[int] = ..., thread_state: _Optional[int] = ..., error: _Optional[str] = ...) -> None: ...

class ThreadIrpEntry(_message.Message):
    __slots__ = ("irp_va", "device_name", "major_fn", "minor_fn", "cancel_routine_va")
    IRP_VA_FIELD_NUMBER: _ClassVar[int]
    DEVICE_NAME_FIELD_NUMBER: _ClassVar[int]
    MAJOR_FN_FIELD_NUMBER: _ClassVar[int]
    MINOR_FN_FIELD_NUMBER: _ClassVar[int]
    CANCEL_ROUTINE_VA_FIELD_NUMBER: _ClassVar[int]
    irp_va: int
    device_name: str
    major_fn: int
    minor_fn: int
    cancel_routine_va: int
    def __init__(self, irp_va: _Optional[int] = ..., device_name: _Optional[str] = ..., major_fn: _Optional[int] = ..., minor_fn: _Optional[int] = ..., cancel_routine_va: _Optional[int] = ...) -> None: ...

class ThreadIrpListRequest(_message.Message):
    __slots__ = ("tid",)
    TID_FIELD_NUMBER: _ClassVar[int]
    tid: int
    def __init__(self, tid: _Optional[int] = ...) -> None: ...

class ThreadIrpListResponse(_message.Message):
    __slots__ = ("status", "pending", "irp_count", "irps", "error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PENDING_FIELD_NUMBER: _ClassVar[int]
    IRP_COUNT_FIELD_NUMBER: _ClassVar[int]
    IRPS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    pending: bool
    irp_count: int
    irps: _containers.RepeatedCompositeFieldContainer[ThreadIrpEntry]
    error: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., pending: _Optional[bool] = ..., irp_count: _Optional[int] = ..., irps: _Optional[_Iterable[_Union[ThreadIrpEntry, _Mapping]]] = ..., error: _Optional[str] = ...) -> None: ...

class ThreadImpersonationRequest(_message.Message):
    __slots__ = ("tid",)
    TID_FIELD_NUMBER: _ClassVar[int]
    tid: int
    def __init__(self, tid: _Optional[int] = ...) -> None: ...

class ThreadImpersonationResponse(_message.Message):
    __slots__ = ("status", "present", "user", "level", "is_self", "sid", "error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PRESENT_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    LEVEL_FIELD_NUMBER: _ClassVar[int]
    IS_SELF_FIELD_NUMBER: _ClassVar[int]
    SID_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    present: bool
    user: str
    level: str
    is_self: bool
    sid: str
    error: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., present: _Optional[bool] = ..., user: _Optional[str] = ..., level: _Optional[str] = ..., is_self: _Optional[bool] = ..., sid: _Optional[str] = ..., error: _Optional[str] = ...) -> None: ...

class ThreadComApartmentRequest(_message.Message):
    __slots__ = ("tid",)
    TID_FIELD_NUMBER: _ClassVar[int]
    tid: int
    def __init__(self, tid: _Optional[int] = ...) -> None: ...

class ThreadComApartmentResponse(_message.Message):
    __slots__ = ("status", "type", "flags", "teb_rfo", "error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    TEB_RFO_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    type: str
    flags: _containers.RepeatedScalarFieldContainer[str]
    teb_rfo: int
    error: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., type: _Optional[str] = ..., flags: _Optional[_Iterable[str]] = ..., teb_rfo: _Optional[int] = ..., error: _Optional[str] = ...) -> None: ...

class ThreadRpcUsageRequest(_message.Message):
    __slots__ = ("tid",)
    TID_FIELD_NUMBER: _ClassVar[int]
    tid: int
    def __init__(self, tid: _Optional[int] = ...) -> None: ...

class ThreadRpcUsageResponse(_message.Message):
    __slots__ = ("status", "in_rpc_call", "server", "chain_length", "error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    IN_RPC_CALL_FIELD_NUMBER: _ClassVar[int]
    SERVER_FIELD_NUMBER: _ClassVar[int]
    CHAIN_LENGTH_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    in_rpc_call: bool
    server: str
    chain_length: int
    error: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., in_rpc_call: _Optional[bool] = ..., server: _Optional[str] = ..., chain_length: _Optional[int] = ..., error: _Optional[str] = ...) -> None: ...

class ThreadPowerThrottlingRequest(_message.Message):
    __slots__ = ("tid",)
    TID_FIELD_NUMBER: _ClassVar[int]
    tid: int
    def __init__(self, tid: _Optional[int] = ...) -> None: ...

class ThreadPowerThrottlingResponse(_message.Message):
    __slots__ = ("status", "control_mask", "state_mask", "error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CONTROL_MASK_FIELD_NUMBER: _ClassVar[int]
    STATE_MASK_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    control_mask: int
    state_mask: int
    error: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., control_mask: _Optional[int] = ..., state_mask: _Optional[int] = ..., error: _Optional[str] = ...) -> None: ...

class ThreadFiberRequest(_message.Message):
    __slots__ = ("tid",)
    TID_FIELD_NUMBER: _ClassVar[int]
    tid: int
    def __init__(self, tid: _Optional[int] = ...) -> None: ...

class ThreadFiberResponse(_message.Message):
    __slots__ = ("status", "has_fiber_data", "error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HAS_FIBER_DATA_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    has_fiber_data: bool
    error: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., has_fiber_data: _Optional[bool] = ..., error: _Optional[str] = ...) -> None: ...

class ScanSpan(_message.Message):
    __slots__ = ("va", "size")
    VA_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    va: int
    size: int
    def __init__(self, va: _Optional[int] = ..., size: _Optional[int] = ...) -> None: ...

class ScanProgress(_message.Message):
    __slots__ = ("bytes_scanned", "bytes_total", "chunks_read", "chunks_skipped", "hits_so_far", "reads_failed")
    BYTES_SCANNED_FIELD_NUMBER: _ClassVar[int]
    BYTES_TOTAL_FIELD_NUMBER: _ClassVar[int]
    CHUNKS_READ_FIELD_NUMBER: _ClassVar[int]
    CHUNKS_SKIPPED_FIELD_NUMBER: _ClassVar[int]
    HITS_SO_FAR_FIELD_NUMBER: _ClassVar[int]
    READS_FAILED_FIELD_NUMBER: _ClassVar[int]
    bytes_scanned: int
    bytes_total: int
    chunks_read: int
    chunks_skipped: int
    hits_so_far: int
    reads_failed: int
    def __init__(self, bytes_scanned: _Optional[int] = ..., bytes_total: _Optional[int] = ..., chunks_read: _Optional[int] = ..., chunks_skipped: _Optional[int] = ..., hits_so_far: _Optional[int] = ..., reads_failed: _Optional[int] = ...) -> None: ...

class ScanEntry(_message.Message):
    __slots__ = ("scan_id", "pid", "space", "value_type", "width", "status", "generation", "hit_count", "created_ts_ms", "owner_client_id", "disk_bytes", "ram_bytes")
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    VALUE_TYPE_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    HIT_COUNT_FIELD_NUMBER: _ClassVar[int]
    CREATED_TS_MS_FIELD_NUMBER: _ClassVar[int]
    OWNER_CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    DISK_BYTES_FIELD_NUMBER: _ClassVar[int]
    RAM_BYTES_FIELD_NUMBER: _ClassVar[int]
    scan_id: str
    pid: int
    space: MemSpace
    value_type: str
    width: int
    status: str
    generation: int
    hit_count: int
    created_ts_ms: int
    owner_client_id: str
    disk_bytes: int
    ram_bytes: int
    def __init__(self, scan_id: _Optional[str] = ..., pid: _Optional[int] = ..., space: _Optional[_Union[MemSpace, str]] = ..., value_type: _Optional[str] = ..., width: _Optional[int] = ..., status: _Optional[str] = ..., generation: _Optional[int] = ..., hit_count: _Optional[int] = ..., created_ts_ms: _Optional[int] = ..., owner_client_id: _Optional[str] = ..., disk_bytes: _Optional[int] = ..., ram_bytes: _Optional[int] = ...) -> None: ...

class ScanCreateRequest(_message.Message):
    __slots__ = ("scan_id", "pid", "space", "value_type", "endian", "encoding", "align", "op", "value_le", "value_hi_le", "tolerance_bits", "spans", "max_results", "owner_client_id", "disk_spill_mode")
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    VALUE_TYPE_FIELD_NUMBER: _ClassVar[int]
    ENDIAN_FIELD_NUMBER: _ClassVar[int]
    ENCODING_FIELD_NUMBER: _ClassVar[int]
    ALIGN_FIELD_NUMBER: _ClassVar[int]
    OP_FIELD_NUMBER: _ClassVar[int]
    VALUE_LE_FIELD_NUMBER: _ClassVar[int]
    VALUE_HI_LE_FIELD_NUMBER: _ClassVar[int]
    TOLERANCE_BITS_FIELD_NUMBER: _ClassVar[int]
    SPANS_FIELD_NUMBER: _ClassVar[int]
    MAX_RESULTS_FIELD_NUMBER: _ClassVar[int]
    OWNER_CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    DISK_SPILL_MODE_FIELD_NUMBER: _ClassVar[int]
    scan_id: str
    pid: int
    space: MemSpace
    value_type: str
    endian: str
    encoding: str
    align: int
    op: str
    value_le: bytes
    value_hi_le: bytes
    tolerance_bits: int
    spans: _containers.RepeatedCompositeFieldContainer[ScanSpan]
    max_results: int
    owner_client_id: str
    disk_spill_mode: ScanDiskSpillMode
    def __init__(self, scan_id: _Optional[str] = ..., pid: _Optional[int] = ..., space: _Optional[_Union[MemSpace, str]] = ..., value_type: _Optional[str] = ..., endian: _Optional[str] = ..., encoding: _Optional[str] = ..., align: _Optional[int] = ..., op: _Optional[str] = ..., value_le: _Optional[bytes] = ..., value_hi_le: _Optional[bytes] = ..., tolerance_bits: _Optional[int] = ..., spans: _Optional[_Iterable[_Union[ScanSpan, _Mapping]]] = ..., max_results: _Optional[int] = ..., owner_client_id: _Optional[str] = ..., disk_spill_mode: _Optional[_Union[ScanDiskSpillMode, str]] = ...) -> None: ...

class ScanCreateResponse(_message.Message):
    __slots__ = ("status", "scan_id", "status_s", "generation", "progress")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_S_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    scan_id: str
    status_s: str
    generation: int
    progress: ScanProgress
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., scan_id: _Optional[str] = ..., status_s: _Optional[str] = ..., generation: _Optional[int] = ..., progress: _Optional[_Union[ScanProgress, _Mapping]] = ...) -> None: ...

class ScanRefineRequest(_message.Message):
    __slots__ = ("scan_id", "op", "value_le", "value_hi_le", "delta_le", "tolerance_bits")
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    OP_FIELD_NUMBER: _ClassVar[int]
    VALUE_LE_FIELD_NUMBER: _ClassVar[int]
    VALUE_HI_LE_FIELD_NUMBER: _ClassVar[int]
    DELTA_LE_FIELD_NUMBER: _ClassVar[int]
    TOLERANCE_BITS_FIELD_NUMBER: _ClassVar[int]
    scan_id: str
    op: str
    value_le: bytes
    value_hi_le: bytes
    delta_le: bytes
    tolerance_bits: int
    def __init__(self, scan_id: _Optional[str] = ..., op: _Optional[str] = ..., value_le: _Optional[bytes] = ..., value_hi_le: _Optional[bytes] = ..., delta_le: _Optional[bytes] = ..., tolerance_bits: _Optional[int] = ...) -> None: ...

class ScanRefineResponse(_message.Message):
    __slots__ = ("status", "scan_id", "generation", "hit_count", "dropped", "reads_failed", "status_s")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    HIT_COUNT_FIELD_NUMBER: _ClassVar[int]
    DROPPED_FIELD_NUMBER: _ClassVar[int]
    READS_FAILED_FIELD_NUMBER: _ClassVar[int]
    STATUS_S_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    scan_id: str
    generation: int
    hit_count: int
    dropped: int
    reads_failed: int
    status_s: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., scan_id: _Optional[str] = ..., generation: _Optional[int] = ..., hit_count: _Optional[int] = ..., dropped: _Optional[int] = ..., reads_failed: _Optional[int] = ..., status_s: _Optional[str] = ...) -> None: ...

class ScanUndoRequest(_message.Message):
    __slots__ = ("scan_id",)
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    scan_id: str
    def __init__(self, scan_id: _Optional[str] = ...) -> None: ...

class ScanUndoResponse(_message.Message):
    __slots__ = ("status", "scan_id", "generation", "hit_count")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    HIT_COUNT_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    scan_id: str
    generation: int
    hit_count: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., scan_id: _Optional[str] = ..., generation: _Optional[int] = ..., hit_count: _Optional[int] = ...) -> None: ...

class ScanFetchRequest(_message.Message):
    __slots__ = ("scan_id", "limit", "offset", "generation")
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    scan_id: str
    limit: int
    offset: int
    generation: int
    def __init__(self, scan_id: _Optional[str] = ..., limit: _Optional[int] = ..., offset: _Optional[int] = ..., generation: _Optional[int] = ...) -> None: ...

class ScanRow(_message.Message):
    __slots__ = ("va", "raw_value")
    VA_FIELD_NUMBER: _ClassVar[int]
    RAW_VALUE_FIELD_NUMBER: _ClassVar[int]
    va: int
    raw_value: bytes
    def __init__(self, va: _Optional[int] = ..., raw_value: _Optional[bytes] = ...) -> None: ...

class ScanFetchChunk(_message.Message):
    __slots__ = ("status", "generation", "rows", "eof", "total_remaining")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    EOF_FIELD_NUMBER: _ClassVar[int]
    TOTAL_REMAINING_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    generation: int
    rows: _containers.RepeatedCompositeFieldContainer[ScanRow]
    eof: bool
    total_remaining: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., generation: _Optional[int] = ..., rows: _Optional[_Iterable[_Union[ScanRow, _Mapping]]] = ..., eof: _Optional[bool] = ..., total_remaining: _Optional[int] = ...) -> None: ...

class ScanCancelRequest(_message.Message):
    __slots__ = ("scan_id",)
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    scan_id: str
    def __init__(self, scan_id: _Optional[str] = ...) -> None: ...

class ScanCancelResponse(_message.Message):
    __slots__ = ("status", "scan_id", "status_s")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_S_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    scan_id: str
    status_s: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., scan_id: _Optional[str] = ..., status_s: _Optional[str] = ...) -> None: ...

class ScanDestroyRequest(_message.Message):
    __slots__ = ("scan_id",)
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    scan_id: str
    def __init__(self, scan_id: _Optional[str] = ...) -> None: ...

class ScanDestroyResponse(_message.Message):
    __slots__ = ("status", "scan_id", "disk_bytes_freed", "ram_bytes_freed")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    DISK_BYTES_FREED_FIELD_NUMBER: _ClassVar[int]
    RAM_BYTES_FREED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    scan_id: str
    disk_bytes_freed: int
    ram_bytes_freed: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., scan_id: _Optional[str] = ..., disk_bytes_freed: _Optional[int] = ..., ram_bytes_freed: _Optional[int] = ...) -> None: ...

class ScanListRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ScanListResponse(_message.Message):
    __slots__ = ("status", "entries")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    entries: _containers.RepeatedCompositeFieldContainer[ScanEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., entries: _Optional[_Iterable[_Union[ScanEntry, _Mapping]]] = ...) -> None: ...

class ScanStatusRequest(_message.Message):
    __slots__ = ("scan_id",)
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    scan_id: str
    def __init__(self, scan_id: _Optional[str] = ...) -> None: ...

class ScanStatusResponse(_message.Message):
    __slots__ = ("status", "scan_id", "status_s", "generation", "hit_count", "progress", "error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_S_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    HIT_COUNT_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    scan_id: str
    status_s: str
    generation: int
    hit_count: int
    progress: ScanProgress
    error: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., scan_id: _Optional[str] = ..., status_s: _Optional[str] = ..., generation: _Optional[int] = ..., hit_count: _Optional[int] = ..., progress: _Optional[_Union[ScanProgress, _Mapping]] = ..., error: _Optional[str] = ...) -> None: ...

class PointerMapProgress(_message.Message):
    __slots__ = ("regions_scanned", "regions_total", "bytes_scanned", "bytes_total", "candidates_so_far", "chunks_skipped")
    REGIONS_SCANNED_FIELD_NUMBER: _ClassVar[int]
    REGIONS_TOTAL_FIELD_NUMBER: _ClassVar[int]
    BYTES_SCANNED_FIELD_NUMBER: _ClassVar[int]
    BYTES_TOTAL_FIELD_NUMBER: _ClassVar[int]
    CANDIDATES_SO_FAR_FIELD_NUMBER: _ClassVar[int]
    CHUNKS_SKIPPED_FIELD_NUMBER: _ClassVar[int]
    regions_scanned: int
    regions_total: int
    bytes_scanned: int
    bytes_total: int
    candidates_so_far: int
    chunks_skipped: int
    def __init__(self, regions_scanned: _Optional[int] = ..., regions_total: _Optional[int] = ..., bytes_scanned: _Optional[int] = ..., bytes_total: _Optional[int] = ..., candidates_so_far: _Optional[int] = ..., chunks_skipped: _Optional[int] = ...) -> None: ...

class PointerMapCreateRequest(_message.Message):
    __slots__ = ("map_id", "pid", "space", "spans", "max_candidates", "owner_client_id", "disk_spill_mode")
    MAP_ID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    SPANS_FIELD_NUMBER: _ClassVar[int]
    MAX_CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    OWNER_CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    DISK_SPILL_MODE_FIELD_NUMBER: _ClassVar[int]
    map_id: str
    pid: int
    space: MemSpace
    spans: _containers.RepeatedCompositeFieldContainer[ScanSpan]
    max_candidates: int
    owner_client_id: str
    disk_spill_mode: ScanDiskSpillMode
    def __init__(self, map_id: _Optional[str] = ..., pid: _Optional[int] = ..., space: _Optional[_Union[MemSpace, str]] = ..., spans: _Optional[_Iterable[_Union[ScanSpan, _Mapping]]] = ..., max_candidates: _Optional[int] = ..., owner_client_id: _Optional[str] = ..., disk_spill_mode: _Optional[_Union[ScanDiskSpillMode, str]] = ...) -> None: ...

class PointerMapCreateResponse(_message.Message):
    __slots__ = ("status", "map_id", "status_s", "progress")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MAP_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_S_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    map_id: str
    status_s: str
    progress: PointerMapProgress
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., map_id: _Optional[str] = ..., status_s: _Optional[str] = ..., progress: _Optional[_Union[PointerMapProgress, _Mapping]] = ...) -> None: ...

class PointerMapStatusRequest(_message.Message):
    __slots__ = ("map_id",)
    MAP_ID_FIELD_NUMBER: _ClassVar[int]
    map_id: str
    def __init__(self, map_id: _Optional[str] = ...) -> None: ...

class PointerMapStatusResponse(_message.Message):
    __slots__ = ("status", "map_id", "status_s", "progress", "entries", "disk_bytes", "error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MAP_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_S_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    DISK_BYTES_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    map_id: str
    status_s: str
    progress: PointerMapProgress
    entries: int
    disk_bytes: int
    error: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., map_id: _Optional[str] = ..., status_s: _Optional[str] = ..., progress: _Optional[_Union[PointerMapProgress, _Mapping]] = ..., entries: _Optional[int] = ..., disk_bytes: _Optional[int] = ..., error: _Optional[str] = ...) -> None: ...

class PointerMapListRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PointerMapListEntry(_message.Message):
    __slots__ = ("map_id", "pid", "space", "status_s", "entries", "disk_bytes", "created_ts_ms", "needs_load")
    MAP_ID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    STATUS_S_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    DISK_BYTES_FIELD_NUMBER: _ClassVar[int]
    CREATED_TS_MS_FIELD_NUMBER: _ClassVar[int]
    NEEDS_LOAD_FIELD_NUMBER: _ClassVar[int]
    map_id: str
    pid: int
    space: MemSpace
    status_s: str
    entries: int
    disk_bytes: int
    created_ts_ms: int
    needs_load: bool
    def __init__(self, map_id: _Optional[str] = ..., pid: _Optional[int] = ..., space: _Optional[_Union[MemSpace, str]] = ..., status_s: _Optional[str] = ..., entries: _Optional[int] = ..., disk_bytes: _Optional[int] = ..., created_ts_ms: _Optional[int] = ..., needs_load: _Optional[bool] = ...) -> None: ...

class PointerMapListResponse(_message.Message):
    __slots__ = ("status", "entries")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    entries: _containers.RepeatedCompositeFieldContainer[PointerMapListEntry]
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., entries: _Optional[_Iterable[_Union[PointerMapListEntry, _Mapping]]] = ...) -> None: ...

class PointerMapCancelRequest(_message.Message):
    __slots__ = ("map_id",)
    MAP_ID_FIELD_NUMBER: _ClassVar[int]
    map_id: str
    def __init__(self, map_id: _Optional[str] = ...) -> None: ...

class PointerMapCancelResponse(_message.Message):
    __slots__ = ("status", "map_id", "status_s")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MAP_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_S_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    map_id: str
    status_s: str
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., map_id: _Optional[str] = ..., status_s: _Optional[str] = ...) -> None: ...

class PointerMapSaveRequest(_message.Message):
    __slots__ = ("map_id", "remote_path")
    MAP_ID_FIELD_NUMBER: _ClassVar[int]
    REMOTE_PATH_FIELD_NUMBER: _ClassVar[int]
    map_id: str
    remote_path: str
    def __init__(self, map_id: _Optional[str] = ..., remote_path: _Optional[str] = ...) -> None: ...

class PointerMapSaveResponse(_message.Message):
    __slots__ = ("status", "bytes_written")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    BYTES_WRITTEN_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    bytes_written: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., bytes_written: _Optional[int] = ...) -> None: ...

class PointerMapLoadRequest(_message.Message):
    __slots__ = ("remote_path", "map_id")
    REMOTE_PATH_FIELD_NUMBER: _ClassVar[int]
    MAP_ID_FIELD_NUMBER: _ClassVar[int]
    remote_path: str
    map_id: str
    def __init__(self, remote_path: _Optional[str] = ..., map_id: _Optional[str] = ...) -> None: ...

class PointerMapLoadResponse(_message.Message):
    __slots__ = ("status", "map_id", "entries")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MAP_ID_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    map_id: str
    entries: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., map_id: _Optional[str] = ..., entries: _Optional[int] = ...) -> None: ...

class PointerMapDestroyRequest(_message.Message):
    __slots__ = ("map_id", "keep_disk")
    MAP_ID_FIELD_NUMBER: _ClassVar[int]
    KEEP_DISK_FIELD_NUMBER: _ClassVar[int]
    map_id: str
    keep_disk: bool
    def __init__(self, map_id: _Optional[str] = ..., keep_disk: _Optional[bool] = ...) -> None: ...

class PointerMapDestroyResponse(_message.Message):
    __slots__ = ("status", "ram_bytes_freed", "disk_bytes_freed")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RAM_BYTES_FREED_FIELD_NUMBER: _ClassVar[int]
    DISK_BYTES_FREED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    ram_bytes_freed: int
    disk_bytes_freed: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., ram_bytes_freed: _Optional[int] = ..., disk_bytes_freed: _Optional[int] = ...) -> None: ...

class PointerScanRequest(_message.Message):
    __slots__ = ("map_id", "target_va", "max_depth", "max_offset", "static_only", "max_results", "fanout_per_level", "wall_ms")
    MAP_ID_FIELD_NUMBER: _ClassVar[int]
    TARGET_VA_FIELD_NUMBER: _ClassVar[int]
    MAX_DEPTH_FIELD_NUMBER: _ClassVar[int]
    MAX_OFFSET_FIELD_NUMBER: _ClassVar[int]
    STATIC_ONLY_FIELD_NUMBER: _ClassVar[int]
    MAX_RESULTS_FIELD_NUMBER: _ClassVar[int]
    FANOUT_PER_LEVEL_FIELD_NUMBER: _ClassVar[int]
    WALL_MS_FIELD_NUMBER: _ClassVar[int]
    map_id: str
    target_va: int
    max_depth: int
    max_offset: int
    static_only: bool
    max_results: int
    fanout_per_level: int
    wall_ms: int
    def __init__(self, map_id: _Optional[str] = ..., target_va: _Optional[int] = ..., max_depth: _Optional[int] = ..., max_offset: _Optional[int] = ..., static_only: _Optional[bool] = ..., max_results: _Optional[int] = ..., fanout_per_level: _Optional[int] = ..., wall_ms: _Optional[int] = ...) -> None: ...

class PointerScanChain(_message.Message):
    __slots__ = ("anchor_va", "anchor_module", "anchor_module_off", "anchor_class", "offsets", "static_")
    ANCHOR_VA_FIELD_NUMBER: _ClassVar[int]
    ANCHOR_MODULE_FIELD_NUMBER: _ClassVar[int]
    ANCHOR_MODULE_OFF_FIELD_NUMBER: _ClassVar[int]
    ANCHOR_CLASS_FIELD_NUMBER: _ClassVar[int]
    OFFSETS_FIELD_NUMBER: _ClassVar[int]
    STATIC__FIELD_NUMBER: _ClassVar[int]
    anchor_va: int
    anchor_module: str
    anchor_module_off: int
    anchor_class: str
    offsets: _containers.RepeatedScalarFieldContainer[int]
    static_: bool
    def __init__(self, anchor_va: _Optional[int] = ..., anchor_module: _Optional[str] = ..., anchor_module_off: _Optional[int] = ..., anchor_class: _Optional[str] = ..., offsets: _Optional[_Iterable[int]] = ..., static_: _Optional[bool] = ...) -> None: ...

class PointerScanResponse(_message.Message):
    __slots__ = ("status", "chains", "truncated", "wall_ms_actual", "candidates_examined", "wall_exceeded", "fanout_exceeded")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CHAINS_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    WALL_MS_ACTUAL_FIELD_NUMBER: _ClassVar[int]
    CANDIDATES_EXAMINED_FIELD_NUMBER: _ClassVar[int]
    WALL_EXCEEDED_FIELD_NUMBER: _ClassVar[int]
    FANOUT_EXCEEDED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    chains: _containers.RepeatedCompositeFieldContainer[PointerScanChain]
    truncated: bool
    wall_ms_actual: int
    candidates_examined: int
    wall_exceeded: bool
    fanout_exceeded: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., chains: _Optional[_Iterable[_Union[PointerScanChain, _Mapping]]] = ..., truncated: _Optional[bool] = ..., wall_ms_actual: _Optional[int] = ..., candidates_examined: _Optional[int] = ..., wall_exceeded: _Optional[bool] = ..., fanout_exceeded: _Optional[bool] = ...) -> None: ...

class PointerMapDiffRequest(_message.Message):
    __slots__ = ("map_id_a", "map_id_b", "static_only", "chains")
    MAP_ID_A_FIELD_NUMBER: _ClassVar[int]
    MAP_ID_B_FIELD_NUMBER: _ClassVar[int]
    STATIC_ONLY_FIELD_NUMBER: _ClassVar[int]
    CHAINS_FIELD_NUMBER: _ClassVar[int]
    map_id_a: str
    map_id_b: str
    static_only: bool
    chains: _containers.RepeatedCompositeFieldContainer[PointerScanChain]
    def __init__(self, map_id_a: _Optional[str] = ..., map_id_b: _Optional[str] = ..., static_only: _Optional[bool] = ..., chains: _Optional[_Iterable[_Union[PointerScanChain, _Mapping]]] = ...) -> None: ...

class PointerMapDiffRow(_message.Message):
    __slots__ = ("source_va_a", "source_va_b", "target_va_a", "target_va_b", "canonical_target", "still_valid", "drift_reason")
    SOURCE_VA_A_FIELD_NUMBER: _ClassVar[int]
    SOURCE_VA_B_FIELD_NUMBER: _ClassVar[int]
    TARGET_VA_A_FIELD_NUMBER: _ClassVar[int]
    TARGET_VA_B_FIELD_NUMBER: _ClassVar[int]
    CANONICAL_TARGET_FIELD_NUMBER: _ClassVar[int]
    STILL_VALID_FIELD_NUMBER: _ClassVar[int]
    DRIFT_REASON_FIELD_NUMBER: _ClassVar[int]
    source_va_a: int
    source_va_b: int
    target_va_a: int
    target_va_b: int
    canonical_target: str
    still_valid: bool
    drift_reason: str
    def __init__(self, source_va_a: _Optional[int] = ..., source_va_b: _Optional[int] = ..., target_va_a: _Optional[int] = ..., target_va_b: _Optional[int] = ..., canonical_target: _Optional[str] = ..., still_valid: _Optional[bool] = ..., drift_reason: _Optional[str] = ...) -> None: ...

class PointerMapDiffResponse(_message.Message):
    __slots__ = ("status", "rows", "compared_entries", "truncated")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    COMPARED_ENTRIES_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    rows: _containers.RepeatedCompositeFieldContainer[PointerMapDiffRow]
    compared_entries: int
    truncated: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., rows: _Optional[_Iterable[_Union[PointerMapDiffRow, _Mapping]]] = ..., compared_entries: _Optional[int] = ..., truncated: _Optional[bool] = ...) -> None: ...

class DissectSlot(_message.Message):
    __slots__ = ("offset", "va", "u64_le", "i32_le", "u32_le", "f32_le", "f64_le", "ptr_target_va", "ptr_module", "ptr_module_off", "ptr_classification", "ascii_prefix", "utf16_prefix", "probable_type", "score_pointer", "score_utf16", "score_ascii", "score_f64", "score_f32")
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    VA_FIELD_NUMBER: _ClassVar[int]
    U64_LE_FIELD_NUMBER: _ClassVar[int]
    I32_LE_FIELD_NUMBER: _ClassVar[int]
    U32_LE_FIELD_NUMBER: _ClassVar[int]
    F32_LE_FIELD_NUMBER: _ClassVar[int]
    F64_LE_FIELD_NUMBER: _ClassVar[int]
    PTR_TARGET_VA_FIELD_NUMBER: _ClassVar[int]
    PTR_MODULE_FIELD_NUMBER: _ClassVar[int]
    PTR_MODULE_OFF_FIELD_NUMBER: _ClassVar[int]
    PTR_CLASSIFICATION_FIELD_NUMBER: _ClassVar[int]
    ASCII_PREFIX_FIELD_NUMBER: _ClassVar[int]
    UTF16_PREFIX_FIELD_NUMBER: _ClassVar[int]
    PROBABLE_TYPE_FIELD_NUMBER: _ClassVar[int]
    SCORE_POINTER_FIELD_NUMBER: _ClassVar[int]
    SCORE_UTF16_FIELD_NUMBER: _ClassVar[int]
    SCORE_ASCII_FIELD_NUMBER: _ClassVar[int]
    SCORE_F64_FIELD_NUMBER: _ClassVar[int]
    SCORE_F32_FIELD_NUMBER: _ClassVar[int]
    offset: int
    va: int
    u64_le: int
    i32_le: int
    u32_le: int
    f32_le: float
    f64_le: float
    ptr_target_va: int
    ptr_module: str
    ptr_module_off: int
    ptr_classification: str
    ascii_prefix: str
    utf16_prefix: str
    probable_type: str
    score_pointer: int
    score_utf16: int
    score_ascii: int
    score_f64: int
    score_f32: int
    def __init__(self, offset: _Optional[int] = ..., va: _Optional[int] = ..., u64_le: _Optional[int] = ..., i32_le: _Optional[int] = ..., u32_le: _Optional[int] = ..., f32_le: _Optional[float] = ..., f64_le: _Optional[float] = ..., ptr_target_va: _Optional[int] = ..., ptr_module: _Optional[str] = ..., ptr_module_off: _Optional[int] = ..., ptr_classification: _Optional[str] = ..., ascii_prefix: _Optional[str] = ..., utf16_prefix: _Optional[str] = ..., probable_type: _Optional[str] = ..., score_pointer: _Optional[int] = ..., score_utf16: _Optional[int] = ..., score_ascii: _Optional[int] = ..., score_f64: _Optional[int] = ..., score_f32: _Optional[int] = ...) -> None: ...

class DissectRequest(_message.Message):
    __slots__ = ("pid", "address", "size", "space", "with_modules", "decode", "align")
    PID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    WITH_MODULES_FIELD_NUMBER: _ClassVar[int]
    DECODE_FIELD_NUMBER: _ClassVar[int]
    ALIGN_FIELD_NUMBER: _ClassVar[int]
    pid: int
    address: int
    size: int
    space: MemSpace
    with_modules: bool
    decode: _containers.RepeatedScalarFieldContainer[str]
    align: int
    def __init__(self, pid: _Optional[int] = ..., address: _Optional[int] = ..., size: _Optional[int] = ..., space: _Optional[_Union[MemSpace, str]] = ..., with_modules: _Optional[bool] = ..., decode: _Optional[_Iterable[str]] = ..., align: _Optional[int] = ...) -> None: ...

class DissectResponse(_message.Message):
    __slots__ = ("status", "slots", "total_rows", "truncated")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SLOTS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_ROWS_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    slots: _containers.RepeatedCompositeFieldContainer[DissectSlot]
    total_rows: int
    truncated: bool
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., slots: _Optional[_Iterable[_Union[DissectSlot, _Mapping]]] = ..., total_rows: _Optional[int] = ..., truncated: _Optional[bool] = ...) -> None: ...

class DissectCompareRequest(_message.Message):
    __slots__ = ("pid", "base_vas", "window_size", "align", "space", "with_modules", "shared_ptr_min_vote", "min_instances_for_class")
    PID_FIELD_NUMBER: _ClassVar[int]
    BASE_VAS_FIELD_NUMBER: _ClassVar[int]
    WINDOW_SIZE_FIELD_NUMBER: _ClassVar[int]
    ALIGN_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    WITH_MODULES_FIELD_NUMBER: _ClassVar[int]
    SHARED_PTR_MIN_VOTE_FIELD_NUMBER: _ClassVar[int]
    MIN_INSTANCES_FOR_CLASS_FIELD_NUMBER: _ClassVar[int]
    pid: int
    base_vas: _containers.RepeatedScalarFieldContainer[int]
    window_size: int
    align: int
    space: MemSpace
    with_modules: bool
    shared_ptr_min_vote: int
    min_instances_for_class: int
    def __init__(self, pid: _Optional[int] = ..., base_vas: _Optional[_Iterable[int]] = ..., window_size: _Optional[int] = ..., align: _Optional[int] = ..., space: _Optional[_Union[MemSpace, str]] = ..., with_modules: _Optional[bool] = ..., shared_ptr_min_vote: _Optional[int] = ..., min_instances_for_class: _Optional[int] = ...) -> None: ...

class DissectOffsetClass(_message.Message):
    __slots__ = ("offset", "classification", "distinct_values", "readable_instances", "modal_value", "modal_votes", "probable_type", "shared_target_module", "shared_target_module_off")
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    CLASSIFICATION_FIELD_NUMBER: _ClassVar[int]
    DISTINCT_VALUES_FIELD_NUMBER: _ClassVar[int]
    READABLE_INSTANCES_FIELD_NUMBER: _ClassVar[int]
    MODAL_VALUE_FIELD_NUMBER: _ClassVar[int]
    MODAL_VOTES_FIELD_NUMBER: _ClassVar[int]
    PROBABLE_TYPE_FIELD_NUMBER: _ClassVar[int]
    SHARED_TARGET_MODULE_FIELD_NUMBER: _ClassVar[int]
    SHARED_TARGET_MODULE_OFF_FIELD_NUMBER: _ClassVar[int]
    offset: int
    classification: str
    distinct_values: int
    readable_instances: int
    modal_value: int
    modal_votes: int
    probable_type: str
    shared_target_module: str
    shared_target_module_off: int
    def __init__(self, offset: _Optional[int] = ..., classification: _Optional[str] = ..., distinct_values: _Optional[int] = ..., readable_instances: _Optional[int] = ..., modal_value: _Optional[int] = ..., modal_votes: _Optional[int] = ..., probable_type: _Optional[str] = ..., shared_target_module: _Optional[str] = ..., shared_target_module_off: _Optional[int] = ...) -> None: ...

class DissectInstanceSlots(_message.Message):
    __slots__ = ("base_va", "unreadable", "slots")
    BASE_VA_FIELD_NUMBER: _ClassVar[int]
    UNREADABLE_FIELD_NUMBER: _ClassVar[int]
    SLOTS_FIELD_NUMBER: _ClassVar[int]
    base_va: int
    unreadable: bool
    slots: _containers.RepeatedCompositeFieldContainer[DissectSlot]
    def __init__(self, base_va: _Optional[int] = ..., unreadable: _Optional[bool] = ..., slots: _Optional[_Iterable[_Union[DissectSlot, _Mapping]]] = ...) -> None: ...

class DissectCompareResponse(_message.Message):
    __slots__ = ("status", "offsets", "per_instance", "n_instances", "n_offsets")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    OFFSETS_FIELD_NUMBER: _ClassVar[int]
    PER_INSTANCE_FIELD_NUMBER: _ClassVar[int]
    N_INSTANCES_FIELD_NUMBER: _ClassVar[int]
    N_OFFSETS_FIELD_NUMBER: _ClassVar[int]
    status: OpStatus
    offsets: _containers.RepeatedCompositeFieldContainer[DissectOffsetClass]
    per_instance: _containers.RepeatedCompositeFieldContainer[DissectInstanceSlots]
    n_instances: int
    n_offsets: int
    def __init__(self, status: _Optional[_Union[OpStatus, _Mapping]] = ..., offsets: _Optional[_Iterable[_Union[DissectOffsetClass, _Mapping]]] = ..., per_instance: _Optional[_Iterable[_Union[DissectInstanceSlots, _Mapping]]] = ..., n_instances: _Optional[int] = ..., n_offsets: _Optional[int] = ...) -> None: ...

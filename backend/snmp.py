"""SNMP helpers for v1 / v2c / v3 built on pysnmp's native asyncio API.

Every public function is a coroutine and must be awaited. The classic
synchronous API ships in the same package, but its wrapper calls
``asyncio.get_event_loop()``, which raises in worker threads — so the async
API is used directly and awaited from the poller's event loop (and from
FastAPI handlers, which are async too).

Community strings and v3 keys arrive already decrypted (see app.py).

Two hard requirements shape this module:

* **Every engine must be closed.** ``SnmpEngine()`` lazily starts an
  ``AsyncioDispatcher`` with a ``while True: await sleep(0.5)`` timer task and
  opens a UDP socket. pysnmp has no finalizer, so an engine that is never
  closed leaks one fd and one eternal task *per call* — 50 hosts polling every
  15 s is ~24 000 leaks/hour. ``engine.closeDispatcher()`` in a ``finally``
  releases both (measured: 30 calls, fds 7→37 without it, 7→8 with it).

* **DNS must not be resolved on the event loop.** ``UdpTransportTarget`` calls
  ``socket.getaddrinfo()`` in its constructor, which blocks the loop for the
  whole resolver timeout and freezes every other host, the REST API and the
  SSH websocket. Addresses are therefore resolved off-loop first and pysnmp is
  handed an already-numeric address.
"""
import asyncio
import socket

from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    UsmUserData,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmAesCfb128Protocol,
)
from pysnmp.hlapi.asyncio import (
    UdpTransportTarget,
    bulkWalkCmd,
    getCmd,
    walkCmd,
)
from pysnmp.proto.rfc1902 import (
    OctetString,
    Integer32,
    Counter32,
    Counter64,
    Gauge32,
    Unsigned32,
    TimeTicks,
    IpAddress,
    Opaque,
    Bits,
)

SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"

import pysnmp.hlapi as _hlapi

from .config import DISCOVERY_MAX_OIDS

AUTH_PROTOS = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA224": getattr(_hlapi, "usmHMAC128SHA224AuthProtocol", usmHMACSHAAuthProtocol),
    "SHA256": getattr(_hlapi, "usmHMAC192SHA256AuthProtocol", usmHMACSHAAuthProtocol),
}

PRIV_PROTOS = {
    "DES": usmDESPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES192": getattr(_hlapi, "usmAesCfb192Protocol", usmAesCfb128Protocol),
    "AES256": getattr(_hlapi, "usmAesCfb256Protocol", usmAesCfb128Protocol),
}

_NON_VALUE_TYPES = ("Null", "NoSuchObject", "NoSuchInstance", "EndOfMibView")

# We only ever deal in raw numeric OIDs, so MIB resolution is pure overhead
# (and can stall offline installs looking for MIB files).
_NO_MIB = {"lookupMib": False}


def _auth_data(host):
    version = str(host.get("snmp_version") or "2c")
    if version == "3":
        kwargs = {}
        if host.get("v3_auth_key"):
            proto_name = (host.get("v3_auth_proto") or "SHA").upper()
            kwargs["authKey"] = host["v3_auth_key"]
            kwargs["authProtocol"] = AUTH_PROTOS.get(proto_name, usmHMACSHAAuthProtocol)
            if host.get("v3_priv_key"):
                priv_name = (host.get("v3_priv_proto") or "AES").upper()
                kwargs["privKey"] = host["v3_priv_key"]
                kwargs["privProtocol"] = PRIV_PROTOS.get(priv_name, usmAesCfb128Protocol)
        return UsmUserData(host.get("v3_user") or "", **kwargs)
    mp_model = 0 if version == "1" else 1
    return CommunityData(host.get("community") or "public", mpModel=mp_model)


async def _target(host, timeout, retries):
    """Build a UDP target, resolving DNS off the event loop.

    ``UdpTransportTarget.__init__`` calls ``socket.getaddrinfo()`` itself; a
    slow or unreachable resolver would block the loop for the whole timeout.
    Numeric literals resolve instantly, so this only matters for DNS names.
    """
    address = str(host["address"]).strip().strip("[]")
    port = int(host.get("snmp_port") or 161)
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            address, port, type=socket.SOCK_DGRAM
        )
        resolved = infos[0][4][0]
    except Exception:
        # Hand pysnmp the original name so it reports a proper timeout/error
        # instead of us guessing; the resolver already failed off-loop.
        resolved = address
    return UdpTransportTarget((resolved, port), timeout=timeout, retries=retries)


def _fmt_ticks(seconds: float) -> str:
    total = int(seconds)
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _to_float(text: str):
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def _value_repr(val):
    """Return (display_text, numeric_value_or_None) for a pysnmp value."""
    type_name = type(val).__name__
    if type_name in _NON_VALUE_TYPES:
        return ("", None)
    try:
        if isinstance(val, TimeTicks):
            seconds = int(val) / 100.0
            return (_fmt_ticks(seconds), seconds)
        # IpAddress / Opaque / Bits are OctetString subclasses. Checking the
        # generic branch first turned 192.168.1.1 into the raw bytes
        # "c0a80101" (or control characters) and stored that in samples.value.
        if isinstance(val, IpAddress):
            return (val.prettyPrint(), None)
        if isinstance(val, (Opaque, Bits)):
            return (val.prettyPrint(), None)
        if isinstance(val, OctetString):
            try:
                text = bytes(val).decode("utf-8")
            except Exception:
                text = bytes(val).hex()
            return (text, _to_float(text))
        if isinstance(val, (Integer32, Counter32, Counter64, Gauge32, Unsigned32)):
            return (str(int(val)), float(int(val)))
        return (val.prettyPrint(), None)
    except Exception:
        return (str(val), None)


async def snmp_get_multi(host: dict, oids, timeout: float = 2.5, retries: int = 1):
    """GET several OIDs from one host.

    Returns {"ok": True, "values": {oid: (text, num)}} or
    {"ok": False, "error": "..."} — never raises.
    """
    engine = SnmpEngine()
    try:
        err_ind, err_stat, err_idx, var_binds = await getCmd(
            engine,
            _auth_data(host),
            await _target(host, timeout, retries),
            ContextData(),
            *[ObjectType(ObjectIdentity(o)) for o in oids],
            **_NO_MIB,
        )
        if err_ind:
            return {"ok": False, "error": str(err_ind)}
        if err_stat:
            return {"ok": False, "error": f"{err_stat.prettyPrint()} (index {err_idx})"}
        values = {}
        for name, val in var_binds:
            values[str(name)] = _value_repr(val)
        return {"ok": True, "values": values}
    except Exception as exc:  # noqa: BLE001 - surface any transport error
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        # Without this the engine's dispatcher task and UDP socket leak.
        _close_engine(engine)


def _close_engine(engine):
    try:
        engine.closeDispatcher()
    except Exception:
        pass


async def _probe_leaf(host: dict, oid: str, timeout: float):
    """Return the value text for one exact OID, or None if unknown.

    Distinct from ``snmp_get_multi`` because an agent that does not know the
    instance answers with a ``NoSuchObject`` sentinel, which decodes to the
    same empty string as a genuinely empty value. Falling back to the subtree
    walk in that case returned unrelated rows for empty-but-valid OIDs (empty
    sysName, ifAlias, hrSWRunParameters).
    """
    engine = SnmpEngine()
    try:
        err_ind, err_stat, err_idx, var_binds = await getCmd(
            engine,
            _auth_data(host),
            await _target(host, timeout, 1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            **_NO_MIB,
        )
        if err_ind or err_stat:
            return None
        for name, val in var_binds:
            if str(name).lstrip(".") == oid.lstrip("."):
                if type(val).__name__ in _NON_VALUE_TYPES:
                    return None
                text, _num = _value_repr(val)
                return text
        return None
    except Exception:
        return None
    finally:
        _close_engine(engine)


async def snmp_walk(host: dict, base_oid: str, max_rows: int = 200, timeout: float = 3.0):
    """Walk a subtree, stopping when the OID leaves the base subtree."""
    engine = SnmpEngine()
    rows = []
    try:
        # Users usually paste scalar OIDs ("...sysUpTime.0"). GETNEXT from a
        # leaf returns the *sibling*, so: fetch the leaf itself when it ends in
        # ".0", and only fall back to walking the parent subtree when the agent
        # does not know that exact instance.
        base = str(base_oid).strip().strip(".")
        if not base:
            base = "1.3.6.1.2.1"
        if base.endswith(".0"):
            leaf = await _probe_leaf(host, base, timeout)
            if leaf is not None:
                return {"ok": True, "rows": [{"oid": base, "value": leaf}]}
            base = base.rsplit(".", 2)[0] or "1.3.6.1.2.1"
        version = str(host.get("snmp_version") or "2c")
        args = (
            engine,
            _auth_data(host),
            await _target(host, timeout, 1),
            ContextData(),
        )
        # v1 has no GETBULK, so it walks with GETNEXT; lexicographicMode=False
        # makes the generator stop by itself once the subtree is left.
        if version == "1":
            gen = walkCmd(
                *args,
                ObjectType(ObjectIdentity(base)),
                lexicographicMode=False,
                maxRows=max_rows,
                **_NO_MIB,
            )
        else:
            gen = bulkWalkCmd(
                *args,
                0,
                25,
                ObjectType(ObjectIdentity(base)),
                lexicographicMode=False,
                maxRows=max_rows,
                **_NO_MIB,
            )
        async for err_ind, err_stat, err_idx, var_binds in gen:
            if err_ind:
                return {"ok": False, "error": str(err_ind)}
            if err_stat:
                return {"ok": False, "error": err_stat.prettyPrint()}
            for name, val in var_binds:
                name_str = str(name)
                if type(val).__name__ in _NON_VALUE_TYPES:
                    continue
                text, _num = _value_repr(val)
                rows.append({"oid": name_str, "value": text})
                if len(rows) >= max_rows:
                    return {"ok": True, "rows": rows}
        return {"ok": True, "rows": rows}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        _close_engine(engine)


# OIDs worth polling on essentially every device. Discovery registers
# *everything* a device exposes, but only these start enabled — otherwise a
# switch's full interface table plus every vendor counter would be sampled on
# every poll, which is slow and fills the samples table with noise.
ESSENTIAL_EXACT = frozenset({
    "1.3.6.1.2.1.1.1.0",  # sysDescr
    "1.3.6.1.2.1.1.3.0",  # sysUpTime
    "1.3.6.1.2.1.1.4.0",  # sysContact
    "1.3.6.1.2.1.1.5.0",  # sysName
    "1.3.6.1.2.1.1.6.0",  # sysLocation
    "1.3.6.1.2.1.2.1.0",  # ifNumber
})
ESSENTIAL_PREFIXES = (
    "1.3.6.1.2.1.2.2.1.1.",   # ifIndex
    "1.3.6.1.2.1.2.2.1.2.",   # ifDescr
    "1.3.6.1.2.1.2.2.1.8.",   # ifOperStatus
)


def is_essential_oid(oid: str) -> bool:
    """Whether a discovered OID should be enabled for polling by default."""
    return oid in ESSENTIAL_EXACT or oid.startswith(ESSENTIAL_PREFIXES)


async def discover_oids(host: dict, max_rows: int = None):
    """Walk a device and report everything it exposes.

    Returns {"ok": True, "oids": [(oid, label)], "total": n, "capped": bool} —
    or {"ok": False, "error": ...}. The walk starts at the MIB root, so a real
    device returns its whole tree; ``max_rows`` (DISCOVERY_MAX_OIDS) is the
    safety cap that keeps a pathological agent from registering millions of
    rows.
    """
    if max_rows is None:
        max_rows = DISCOVERY_MAX_OIDS
    result = await snmp_walk(host, "1.3.6.1", max_rows=max_rows, timeout=5.0)
    if not result.get("ok"):
        return {"ok": False, "error": result.get("error", "walk failed")}
    rows = result.get("rows") or []
    oids = [(row["oid"], row["oid"]) for row in rows]
    return {
        "ok": True,
        "oids": oids,
        "total": len(oids),
        "capped": len(rows) >= max_rows,
    }

"""Background poller: reachability checks + SNMP sampling per host.

Each enabled host gets an independent asyncio task looping
``check_host -> sleep(poll_interval)``. State transitions (up/down) are written
to the events table, which is the single source of truth for history, uptime
graphs and downtime periods. A maintenance task prunes old samples and expired
sessions.
"""
import asyncio
import platform
import time

from . import db, security
from . import snmp as snmplib
from .config import EVENT_RETENTION_DAYS, PING_TIMEOUT, SAMPLE_RETENTION_DAYS

_ping_bin_missing_logged = set()


def _compare(value: float, op: str, threshold: float) -> bool:
    """Apply a trigger operator. Unknown operators never fire."""
    if op == ">":
        return value > threshold
    if op == ">=":
        return value >= threshold
    if op == "<":
        return value < threshold
    if op == "<=":
        return value <= threshold
    if op == "==":
        return value == threshold
    if op == "!=":
        return value != threshold
    return False


def _fmt_num(value) -> str:
    """Compact number for event messages (no float noise like 50000.0000001)."""
    if value is None:
        return "—"
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return str(value)


async def ping(address: str, timeout: float = None):
    """ICMP echo check. Returns (ok, detail); ok is None when ping is unusable."""
    if timeout is None:
        timeout = PING_TIMEOUT
    is_darwin = platform.system() == "Darwin"
    if is_darwin:  # -W is milliseconds on the BSD ping
        cmd = ["ping", "-n", "-c", "1", "-W", str(int(timeout * 1000)), address]
    else:  # iputils: -W is seconds
        cmd = ["ping", "-n", "-c", "1", "-W", str(max(1, int(timeout))), address]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return None, "ping binary not found"
    try:
        rc = await asyncio.wait_for(proc.wait(), timeout=timeout + 3)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return False, "timeout"
    if rc == 0:
        return True, "ICMP echo reply"
    return False, f"no ICMP reply (rc={rc})"


async def tcp_check(address: str, port: int, timeout: float = 3.0):
    """TCP connect check. Returns (ok, latency_ms_or_None)."""
    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, round((time.monotonic() - started) * 1000, 1)
    except Exception:
        return False, None


class Poller:
    def __init__(self):
        self.tasks = {}
        self.status = {}
        self._last_snmp_err = {}
        self._maint = None
        self._stopped = False
        self.loop = None
        self._discovering = set()
        self._discover_tasks = {}

    # ------------------------------------------------------------- lifecycle
    async def start(self):
        self.loop = asyncio.get_running_loop()
        db.init()
        for host in await asyncio.to_thread(db.all_hosts):
            await self._init_status(host["id"])
        for host in await asyncio.to_thread(db.all_hosts, True):
            self._spawn(host)
        self._maint = asyncio.create_task(self._maintenance())

    async def stop(self):
        self._stopped = True
        for task in list(self.tasks.values()):
            await self._cancel(task)
        self.tasks.clear()
        # A discovery walk can run for minutes; without this it outlives stop().
        for task in list(self._discover_tasks.values()):
            await self._cancel(task)
        self._discover_tasks.clear()
        if self._maint:
            await self._cancel(self._maint)
            self._maint = None

    @staticmethod
    async def _cancel(task):
        """Cancel a task and await it so it cannot outlive its owner.

        Without the await, a cancelled loop can still be mid-write when the
        process exits, and asyncio logs "Task exception was never retrieved"
        for anything that fails during cancellation.
        """
        if not task:
            return
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    async def _init_status(self, host_id: int):
        if host_id in self.status:
            return
        last = await asyncio.to_thread(db.last_state_event, host_id)
        if last:
            self.status[host_id] = {
                "up": last["type"] == "up",
                "last_change": last["ts"],
                "last_check": last["ts"],
                "detail": "restored from history",
                "latency_ms": None,
            }
        else:
            self.status[host_id] = {
                "up": None,
                "last_change": None,
                "last_check": None,
                "detail": "not checked yet",
                "latency_ms": None,
            }

    async def _spawn(self, host):
        await self._init_status(host["id"])
        old = self.tasks.pop(host["id"], None)
        if old:
            # Synchronous path (called from reload): request cancellation here,
            # the loop collects it on its next tick.
            old.cancel()
        self.tasks[host["id"]] = asyncio.create_task(
            self._host_loop(host["id"], host["poll_interval"])
        )

    def forget_host(self, host_id: int):
        """Drop every trace of a host (called when it is deleted).

        Otherwise `status`, the SNMP error throttle and the ping-missing flag
        keep growing for the lifetime of the process.
        """
        self.status.pop(host_id, None)
        # _last_snmp_err holds two key shapes: a bare host_id (from _sample's
        # query-failure throttle) and a (host_id, type_) tuple (from _log_once).
        # Indexing both as tuples raised TypeError, which aborted reload() and
        # left the ping-missing flag and _discovering entry behind.
        for key in [
            k for k in self._last_snmp_err
            if (k[0] if isinstance(k, tuple) else k) == host_id
        ]:
            self._last_snmp_err.pop(key, None)
        _ping_bin_missing_logged.discard(host_id)
        self._discovering.discard(host_id)
        task = self._discover_tasks.pop(host_id, None)
        if task is not None and not task.done():
            task.cancel()

    async def reload(self, host_id: int = None):
        """Re-read host configuration after CRUD changes."""
        if host_id is not None:
            old = self.tasks.pop(host_id, None)
            if old:
                await self._cancel(old)
            host = await asyncio.to_thread(db.get_host, host_id)
            if host is None:
                self.forget_host(host_id)
            elif host["enabled"]:
                await self._spawn(host)
            else:
                await self._init_status(host_id)
            return
        for task in list(self.tasks.values()):
            await self._cancel(task)
        self.tasks.clear()
        for host in await asyncio.to_thread(db.all_hosts, True):
            await self._spawn(host)

    # ------------------------------------------------------------- main loop
    async def _host_loop(self, host_id: int, interval: int):
        while not self._stopped:
            try:
                await self.check_host(host_id)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # never let a host loop die
                # Rate-limited like every other repetitive error: an
                # unthrottled poll_error row per interval per host grows the
                # events table without bound.
                try:
                    await self._log_once(host_id, "poll_error", f"Poller error: {exc}")
                except Exception:
                    pass
            await asyncio.sleep(max(5, interval))

    async def check_host(self, host_id: int):
        # Every read goes through the same global RLock as the writers
        # (db.py's documented invariant), so a long writer — prune_samples on a
        # big table — would otherwise freeze this loop and the REST API with
        # it. Thread hops are free at poll intervals.
        host = await asyncio.to_thread(db.get_host, host_id)
        if not host or not host["enabled"]:
            return
        try:
            host = security.decrypt_host_secrets(host)
        except RuntimeError as exc:
            state = self.status.setdefault(host_id, {})
            state["detail"] = f"Credential error: {exc}"
            await self._log_once(host_id, "poll_error", f"Credential error: {exc}")
            return
        started = time.monotonic()
        method = host["check_method"]
        if method == "tcp":
            ok, latency = await tcp_check(host["address"], host["check_port"])
            detail = (
                f"TCP port {host['check_port']} open"
                if ok
                else f"TCP port {host['check_port']} closed or filtered"
            )
        elif method == "snmp":
            result = await snmplib.snmp_get_multi(
                host, [snmplib.SYS_UPTIME_OID]
            )
            ok = bool(result.get("ok"))
            detail = (
                "SNMP sysUpTime.0 answered"
                if ok
                else f"SNMP check failed: {result.get('error', 'no response')}"
            )
            latency = None
        else:  # icmp
            ok, detail = await ping(host["address"])
            latency = None
            if ok is None:
                # ping unavailable (missing binary/permissions): record once and
                # leave the state unknown instead of lying "down".
                if host_id not in _ping_bin_missing_logged:
                    _ping_bin_missing_logged.add(host_id)
                    await asyncio.to_thread(
                        db.add_event,
                        host_id,
                        "poll_error",
                        "ICMP check unavailable (ping binary missing?). "
                        "Use TCP or SNMP as check method for this host.",
                    )
                self.status.setdefault(host_id, {})["detail"] = detail
                return

        if latency is None:
            latency = round((time.monotonic() - started) * 1000, 1)

        state = self.status.setdefault(host_id, {})
        previous = state.get("up")
        now = time.time()
        state["last_check"] = now
        state["latency_ms"] = latency
        state["detail"] = detail
        if previous is None or previous != ok:
            # Write the event *before* mutating the in-memory state: a
            # reload()/stop() cancellation landing on the to_thread write
            # otherwise left status ahead of the database, so a restart
            # restored the stale state and the transition was lost.
            if ok:
                await asyncio.to_thread(
                    db.add_event, host_id, "up", f"Host is reachable again ({detail})"
                )
            else:
                await asyncio.to_thread(
                    db.add_event, host_id, "down", f"Host is unreachable ({detail})"
                )
            state["last_change"] = now
            state["up"] = ok
        else:
            state["up"] = ok

        if host["snmp_enabled"]:
            if not host.get("snmp_discovered"):
                # First successful poll on an SNMP host: learn what it exposes.
                # Runs as its own task so a large walk cannot stall this loop,
                # but the task is tracked so stop()/forget_host() can cancel it
                # — an untracked one kept writing rows for a deleted host.
                task = self._discover_tasks.get(host["id"])
                if task is None or task.done():
                    self._discover_tasks[host["id"]] = asyncio.create_task(
                        self._discover(host)
                    )
            await self._sample(host)

    async def _sample(self, host):
        oids = await asyncio.to_thread(db.enabled_oids_for_host, host["id"])
        oids += [oid for oid, _ in db.DEFAULT_OIDS if oid not in oids]
        if not oids:
            return
        result = await snmplib.snmp_get_multi(host, oids)
        if not result.get("ok"):
            now = time.time()
            if now - self._last_snmp_err.get(host["id"], 0) > 300:
                self._last_snmp_err[host["id"]] = now
                await asyncio.to_thread(
                    db.add_event,
                    host["id"],
                    "snmp_error",
                    f"SNMP query failed: {result.get('error', 'no response')}",
                )
            return
        if result.get("partial"):
            # Some OIDs resolved and some did not. The good values are still
            # stored; say which ones failed so a silently unwatched OID is not
            # a mystery.
            await self._log_once(
                host["id"],
                "snmp_error",
                "SNMP partial response, no value for: "
                + ", ".join(result.get("failed") or [])
                + f" ({result.get('error', '')})",
            )
        ts = time.time()
        rows = [
            (host["id"], oid, ts, text, num)
            for oid, (text, num) in result["values"].items()
        ]
        # Snapshot the previous values *before* the new rows land: read after
        # the write, every delta trigger would compare a value with itself.
        previous = await asyncio.to_thread(
            db.last_values_for_oids, host["id"], list(result["values"])
        )
        await asyncio.to_thread(db.add_samples, rows)
        await self._evaluate_triggers(host, result["values"], ts, previous)

    async def _evaluate_triggers(self, host, values, ts, previous):
        """Fire user-defined thresholds against the values just sampled.

        Only OIDs that were actually sampled this round are considered, so a
        disabled OID cannot fire its rule. Each trigger is edge-triggered: it
        fires on the transition into the breached state and re-arms when the
        value leaves it, which is what stops a printer sitting above its page
        limit from writing an event every single poll.
        """
        triggers = await asyncio.to_thread(db.host_triggers, host["id"])
        for trig in triggers:
            if not trig["enabled"] or trig["oid"] not in values:
                continue
            text, num = values[trig["oid"]]
            if num is None:
                # Non-numeric value (a string OID): no comparison is possible.
                continue
            reference = num
            if trig["delta"]:
                prior = previous.get(trig["oid"])
                if not prior or prior["num"] is None:
                    # First sample for this OID: nothing to compare against.
                    continue
                reference = num - prior["num"]
            if not _compare(reference, trig["op"], trig["value"]):
                if trig["breached"]:
                    await asyncio.to_thread(
                        db.set_trigger_state, trig["id"], False, num
                    )
                continue
            if trig["breached"]:
                continue
            await asyncio.to_thread(
                db.set_trigger_state, trig["id"], True, num, fired_ts=ts
            )
            await asyncio.to_thread(
                db.add_event,
                host["id"],
                "trigger",
                f"{trig['label'] or trig['oid']} breached: "
                f"{_fmt_num(reference)} {trig['op']} {_fmt_num(trig['value'])}"
                + (f" (was {_fmt_num(num)})" if trig["delta"] else ""),
            )

    async def _discover(self, host):
        """One-time full walk that registers every OID the device exposes.

        Runs as its own task so a slow or very large agent cannot stall the
        host's reachability loop. Everything found is stored; only the
        essentials start enabled, and the user turns on the rest.
        """
        host_id = host["id"]
        if host_id in self._discovering:
            return
        self._discovering.add(host_id)
        try:
            result = await snmplib.discover_oids(host)
            if not result.get("ok"):
                # Discovery failed (timeout, bad community): leave the host
                # undiscovered so the next poll tries again.
                return
            # The walk can take minutes. If the host was deleted meanwhile,
            # oids.host_id has no foreign key, so these rows would be
            # re-inserted for a host that no longer exists and never pruned.
            if await asyncio.to_thread(db.get_host, host_id) is None:
                return
            rows = [
                (oid, label, int(snmplib.is_essential_oid(oid)))
                for oid, label in result["oids"]
            ]
            await asyncio.to_thread(db.add_oids_bulk, host_id, rows)
            await asyncio.to_thread(db.mark_host_discovered, host_id)
            enabled = sum(1 for _, _, e in rows if e)
            await asyncio.to_thread(
                db.add_event,
                host_id,
                "discovery",
                f"Discovered {len(rows)} OIDs; {enabled} enabled for polling"
                + (" (walk hit the discovery cap)" if result.get("capped") else ""),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # never let discovery kill the poller
            await asyncio.to_thread(
                db.add_event, host_id, "poll_error", f"OID discovery failed: {exc}"
            )
        finally:
            self._discovering.discard(host_id)
            if self._discover_tasks.get(host_id) is asyncio.current_task():
                self._discover_tasks.pop(host_id, None)

    async def _log_once(self, host_id: int, type_: str, message: str, interval: float = 300):
        """Rate-limit repetitive error events (one per interval per host)."""
        now = time.time()
        key = (host_id, type_)
        if now - self._last_snmp_err.get(key, 0) > interval:
            self._last_snmp_err[key] = now
            await asyncio.to_thread(db.add_event, host_id, type_, message)

    # ------------------------------------------------------------- maintenance
    async def _maintenance(self):
        while not self._stopped:
            try:
                # NETMON_RETENTION_DAYS is the default; a stored setting can
                # override it later without making the env var a silent no-op.
                retention_days = int(
                    await asyncio.to_thread(
                        db.get_setting, "retention_days", SAMPLE_RETENTION_DAYS
                    )
                )
                await asyncio.to_thread(
                    db.prune_samples, time.time() - retention_days * 86400
                )
                # Events are the user-facing history (outages, reconnects, SSH
                # sessions); keep them much longer than raw samples but still
                # bound the table so a busy host cannot grow it forever.
                event_retention_days = int(
                    await asyncio.to_thread(
                        db.get_setting, "event_retention_days", EVENT_RETENTION_DAYS
                    )
                )
                await asyncio.to_thread(
                    db.prune_events, time.time() - event_retention_days * 86400
                )
                await asyncio.to_thread(db.purge_expired_sessions)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Never let one bad maintenance cycle silently disable the next.
                print(f"[netmon] maintenance error: {exc}", flush=True)
            await asyncio.sleep(600)

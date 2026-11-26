//! Who listens on a loopback address: this account, the system, or
//! someone else on the same computer.
//!
//! Nothing a client can ask proves that a SOCKS5 proxy is Tor: a fake one
//! can relay to a real Tor and write down everything it carries. What
//! matters is who holds the socket. A proxy opened by the account this
//! app runs as, or by the system, knows nothing the app itself does not;
//! one opened by another account of the same computer sees which onion
//! hosts this wallet talks to, and when.
//!
//! - Linux reads the owner of the listening socket from `/proc/net/tcp`
//!   and `/proc/net/tcp6`. The system is root and the accounts below
//!   `UID_MIN` of `/etc/login.defs` (1000 when it says nothing), never
//!   `nobody` (65534), which any service may run as; root alone when
//!   this account itself is below `UID_MIN`.
//! - Windows asks which process listens (`GetExtendedTcpTable`) and
//!   compares the user of its token with the user of this process. A
//!   process that cannot be opened is nobody this build can name.
//! - macOS and every other platform answer [`LoopbackOwner::Unknown`]:
//!   the owner of a socket there is only found by walking the list of
//!   processes, which the core does not do.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Who holds the socket a proxy on loopback answers from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopbackOwner {
    /// The account this app runs as.
    ThisAccount,
    /// The operating system: root or a service account.
    System,
    /// Another account of this computer.
    OtherAccount,
    /// Nobody this build can name: nothing found listening there, a
    /// table that could not be read, a process that could not be opened,
    /// or a platform where the core cannot tell.
    Unknown,
}

impl LoopbackOwner {
    /// Whether a proxy held by this owner may carry onion traffic
    /// without having been chosen by name.
    pub fn is_trusted(self) -> bool {
        matches!(self, LoopbackOwner::ThisAccount | LoopbackOwner::System)
    }

    /// How much a listener held by this owner is to be feared, when
    /// several could take the connection.
    fn doubt(self) -> u8 {
        match self {
            LoopbackOwner::System => 0,
            LoopbackOwner::ThisAccount => 1,
            LoopbackOwner::Unknown => 2,
            LoopbackOwner::OtherAccount => 3,
        }
    }

    /// The owner of an address several listeners may answer on: the
    /// most doubtful of them, since any could take the connection, and
    /// [`LoopbackOwner::Unknown`] when there is none.
    fn of_all(owners: impl IntoIterator<Item = LoopbackOwner>) -> LoopbackOwner {
        owners
            .into_iter()
            .max_by_key(|owner| owner.doubt())
            .unwrap_or(LoopbackOwner::Unknown)
    }
}

/// How long the name of a proxy gets to resolve. The probe that found
/// it answering resolved it a moment ago, so the answer is in a cache
/// when there is one; the budget only bounds a resolver gone silent.
const RESOLVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// The loopback addresses a connection to `address` may land on, or
/// `None` when it lands on none. The address is resolved as the
/// connection resolves it, so every spelling of loopback is loopback:
/// `127.1`, `2130706433`, `0x7f000001`, `::1:9050` without brackets,
/// `localhost` and every other name the system puts there
/// (`ip6-localhost`, `localhost.localdomain`, the machine's own name).
/// One loopback address among those a name resolves to is enough: the
/// connection may take it. `0.0.0.0` and `::` count as the loopback of
/// their family, where a connection to them lands. An address that does
/// not resolve now is not one nobody holds: it comes back with no
/// candidate, whose owner nobody can name.
pub(crate) async fn loopback_addresses(address: &str) -> Option<Vec<SocketAddr>> {
    match tokio::time::timeout(RESOLVE_BUDGET, tokio::net::lookup_host(address.trim())).await {
        Ok(Ok(resolved)) => on_loopback(resolved),
        Ok(Err(_)) | Err(_) => Some(Vec::new()),
    }
}

/// The addresses of `resolved` a connection reaches loopback by, the
/// wildcards as the loopback of their family, or `None` when there is
/// none.
fn on_loopback(resolved: impl IntoIterator<Item = SocketAddr>) -> Option<Vec<SocketAddr>> {
    let mut loopback: Vec<SocketAddr> = Vec::new();
    for socket in resolved {
        let ip = match socket.ip().to_canonical() {
            IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip => ip,
        };
        let socket = SocketAddr::new(ip, socket.port());
        if ip.is_loopback() && !loopback.contains(&socket) {
            loopback.push(socket);
        }
    }
    (!loopback.is_empty()).then_some(loopback)
}

/// Who listens at `candidates`, the loopback addresses of
/// [`loopback_addresses`]: the most doubtful of the listeners there, and
/// nobody this build can name when there is no candidate. Reads tables
/// of the operating system, off the async runtime.
pub(crate) async fn of(candidates: Vec<SocketAddr>) -> LoopbackOwner {
    if candidates.is_empty() {
        return LoopbackOwner::Unknown;
    }
    tokio::task::spawn_blocking(move || listening_on(&candidates))
        .await
        .unwrap_or(LoopbackOwner::Unknown)
}

/// Whether a socket listening at `listener` takes a connection to
/// `target`: the same port, and the same address or the wildcard of a
/// family that reaches it. An IPv6 wildcard takes IPv4 too unless it was
/// bound IPv6 only, which the tables do not say: counting it errs on the
/// side of doubt.
fn reaches(listener: SocketAddr, target: SocketAddr) -> bool {
    if listener.port() != target.port() {
        return false;
    }
    let (listener, target) = (listener.ip().to_canonical(), target.ip().to_canonical());
    listener == target
        || match listener {
            IpAddr::V4(ip) => ip.is_unspecified() && target.is_ipv4(),
            IpAddr::V6(ip) => ip.is_unspecified(),
        }
}

#[cfg(target_os = "linux")]
fn listening_on(candidates: &[SocketAddr]) -> LoopbackOwner {
    proc_net::listening_on(candidates)
}

#[cfg(windows)]
fn listening_on(candidates: &[SocketAddr]) -> LoopbackOwner {
    windows::listening_on(candidates)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn listening_on(_candidates: &[SocketAddr]) -> LoopbackOwner {
    LoopbackOwner::Unknown
}

/// The Linux tables. Built in tests everywhere, since they are text.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "only Linux reads the tables; the parser is tested everywhere"
    )
)]
mod proc_net {
    use super::*;

    /// Where `/etc/login.defs` says nothing, the first account a person
    /// gets on every common distribution.
    const DEFAULT_UID_MIN: u32 = 1000;
    /// `nobody`: below no `UID_MIN`, and never the system.
    const NOBODY: u32 = 65534;
    /// `TCP_LISTEN`, as the `st` column writes it.
    const LISTEN: &str = "0A";

    #[cfg(target_os = "linux")]
    pub(super) fn listening_on(candidates: &[SocketAddr]) -> LoopbackOwner {
        let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") else {
            return LoopbackOwner::Unknown;
        };
        // A kernel without IPv6 has no such file, and no IPv6 listener.
        let tcp6 = match std::fs::read_to_string("/proc/net/tcp6") {
            Ok(table) => table,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(_) => return LoopbackOwner::Unknown,
        };
        let uid_min = std::fs::read_to_string("/etc/login.defs")
            .ok()
            .and_then(|defs| uid_min(&defs))
            .unwrap_or(DEFAULT_UID_MIN);
        // SAFETY: geteuid takes nothing, cannot fail and touches no memory.
        let euid = unsafe { libc::geteuid() };
        owner_in(candidates, &[&tcp, &tcp6], euid, uid_min)
    }

    /// The owner of `candidates` per the tables, for a process running
    /// as `euid`.
    pub(super) fn owner_in(
        candidates: &[SocketAddr],
        tables: &[&str],
        euid: u32,
        uid_min: u32,
    ) -> LoopbackOwner {
        LoopbackOwner::of_all(
            tables
                .iter()
                .flat_map(|table| listeners(table))
                .filter(|(address, _)| {
                    candidates
                        .iter()
                        .any(|candidate| reaches(*address, *candidate))
                })
                .map(|(_, uid)| classify(uid, euid, uid_min)),
        )
    }

    /// Who an account is, seen from a process running as `euid`. When
    /// this account itself sits below `UID_MIN`, people were given
    /// accounts there, on a computer set up before that value or by
    /// hand: below it no longer says system, and root alone is.
    pub(super) fn classify(uid: u32, euid: u32, uid_min: u32) -> LoopbackOwner {
        let people_below = euid != 0 && euid < uid_min;
        if uid == euid {
            LoopbackOwner::ThisAccount
        } else if uid == 0 || (!people_below && uid != NOBODY && uid < uid_min) {
            LoopbackOwner::System
        } else {
            LoopbackOwner::OtherAccount
        }
    }

    /// The listening sockets of a `/proc/net/tcp` or `tcp6` table, with
    /// the uid that opened each. A line that does not read is skipped.
    pub(super) fn listeners(table: &str) -> impl Iterator<Item = (SocketAddr, u32)> + '_ {
        table.lines().skip(1).filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // sl, local_address, rem_address, st, tx_queue:rx_queue,
            // tr:tm->when, retrnsmt, uid.
            if fields.get(3) != Some(&LISTEN) {
                return None;
            }
            let address = socket_address(fields.get(1)?)?;
            let uid = fields.get(7)?.parse().ok()?;
            Some((address, uid))
        })
    }

    /// `ADDR:PORT` as the kernel writes it: the port in hexadecimal, the
    /// address as the 32-bit words of network order, each printed as the
    /// native integer it reads as. So on a little-endian machine
    /// 127.0.0.1 is `0100007F`.
    pub(super) fn socket_address(field: &str) -> Option<SocketAddr> {
        let (address, port) = field.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let word = |hex: &str| u32::from_str_radix(hex, 16).ok().map(u32::to_ne_bytes);
        let ip = match address.len() {
            8 => IpAddr::V4(Ipv4Addr::from(word(address)?)),
            32 => {
                let mut octets = [0u8; 16];
                for (chunk, out) in octets.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                    *out = word(address.get(chunk * 8..chunk * 8 + 8)?)?;
                }
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return None,
        };
        Some(SocketAddr::new(ip, port))
    }

    /// `UID_MIN` of `/etc/login.defs`, if it names one.
    pub(super) fn uid_min(defs: &str) -> Option<u32> {
        defs.lines().find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "UID_MIN")
                .then(|| words.next()?.parse().ok())
                .flatten()
        })
    }
}

#[cfg(windows)]
mod windows {
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, NO_ERROR,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, IsWellKnownSid, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WinLocalServiceSid, WinLocalSystemSid, WinNetworkServiceSid,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::*;

    /// `AF_INET` and `AF_INET6` of WinSock, as `GetExtendedTcpTable`
    /// takes them; named here rather than pulled from the WinSock
    /// bindings for two numbers.
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;

    pub(super) fn listening_on(candidates: &[SocketAddr]) -> LoopbackOwner {
        let (Some(v4), Some(v6)) = (listeners_v4(), listeners_v6()) else {
            return LoopbackOwner::Unknown;
        };
        let mut pids: Vec<u32> = v4
            .into_iter()
            .chain(v6)
            .filter(|(address, _)| {
                candidates
                    .iter()
                    .any(|candidate| reaches(*address, *candidate))
            })
            .map(|(_, pid)| pid)
            .collect();
        pids.sort_unstable();
        pids.dedup();
        if pids.is_empty() {
            return LoopbackOwner::Unknown;
        }
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
        // closing and is valid for the life of the process.
        let Some(me) = TokenUserOf::process(unsafe { GetCurrentProcess() }) else {
            return LoopbackOwner::Unknown;
        };
        LoopbackOwner::of_all(pids.into_iter().map(|pid| owner_of(pid, &me)))
    }

    /// Who runs process `pid`, next to the user `me` of this process.
    fn owner_of(pid: u32, me: &TokenUserOf) -> LoopbackOwner {
        // SAFETY: OpenProcess takes no pointer, and returns null when the
        // process cannot be opened.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return LoopbackOwner::Unknown;
        }
        let process = Handle(process);
        let Some(user) = TokenUserOf::process(process.0) else {
            return LoopbackOwner::Unknown;
        };
        // SAFETY: both SIDs point into buffers GetTokenInformation filled,
        // which `user` and `me` keep alive for this call.
        if unsafe { EqualSid(user.sid(), me.sid()) } != 0 {
            return LoopbackOwner::ThisAccount;
        }
        let service = [WinLocalSystemSid, WinLocalServiceSid, WinNetworkServiceSid]
            .into_iter()
            // SAFETY: the SID points into the live buffer of `user`.
            .any(|kind| unsafe { IsWellKnownSid(user.sid(), kind) } != 0);
        if service {
            LoopbackOwner::System
        } else {
            LoopbackOwner::OtherAccount
        }
    }

    /// A handle closed when it goes out of scope, on every path.
    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by this module, is closed once,
            // here, and never used after.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// The `TOKEN_USER` of a process, in the buffer that holds its SID.
    /// `u64` words keep it aligned for the pointer it starts with.
    struct TokenUserOf(Vec<u64>);

    impl TokenUserOf {
        fn process(process: HANDLE) -> Option<Self> {
            let mut token: HANDLE = ptr::null_mut();
            // SAFETY: `process` is a live handle with query rights, and
            // `token` is a place for the handle the call writes on success.
            if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
                return None;
            }
            let token = Handle(token);
            let mut needed = 0u32;
            // SAFETY: a null buffer of length 0 only asks for the size,
            // written to `needed`; the call fails by design.
            unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed) };
            if (needed as usize) < size_of::<TOKEN_USER>() {
                return None;
            }
            let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
            // SAFETY: `buffer` is writable for at least `needed` bytes and
            // aligned for TOKEN_USER; the call writes no more than that.
            let read = unsafe {
                GetTokenInformation(
                    token.0,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            };
            (read != 0).then_some(TokenUserOf(buffer))
        }

        fn sid(&self) -> PSID {
            // SAFETY: the buffer holds a TOKEN_USER GetTokenInformation
            // wrote, at its start, aligned and at least that large.
            unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
        }
    }

    /// The listener table of one family, as `GetExtendedTcpTable` fills
    /// it, in `u64` words to keep it aligned for its rows. The table can
    /// grow between the call that sizes it and the one that fills it,
    /// hence the few tries.
    fn table(family: u32) -> Option<Vec<u64>> {
        let mut size = 0u32;
        for _ in 0..4 {
            let mut buffer = vec![0u64; (size as usize).div_ceil(8).max(1)];
            let mut length = u32::try_from(buffer.len() * 8).ok()?;
            // SAFETY: `buffer` is writable for `length` bytes; the call
            // writes no more, or answers ERROR_INSUFFICIENT_BUFFER with the
            // size it needs in `length`.
            let status = unsafe {
                GetExtendedTcpTable(
                    buffer.as_mut_ptr().cast(),
                    &mut length,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            match status {
                NO_ERROR => return Some(buffer),
                ERROR_INSUFFICIENT_BUFFER => size = length,
                _ => return None,
            }
        }
        None
    }

    /// The `count` rows of a table that start `first` bytes into
    /// `buffer`, checked against its length.
    fn rows<Row: Copy>(buffer: &[u64], count: u32, first: usize) -> Option<Vec<Row>> {
        let count = usize::try_from(count).ok()?;
        let end = count.checked_mul(size_of::<Row>())?.checked_add(first)?;
        if end > buffer.len() * 8 {
            return None;
        }
        // SAFETY: the rows lie within the buffer, checked above, at the
        // offset of the table's first row; the buffer is aligned to 8,
        // enough for rows of u32 and bytes, and the call initialized them.
        let rows = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>().add(first).cast::<Row>(), count)
        };
        Some(rows.to_vec())
    }

    /// `dwNumEntries`, the `u32` both tables start with.
    fn entries(buffer: &[u64]) -> u32 {
        // SAFETY: the buffer holds at least one u64, aligned to 8, and
        // the call wrote the count in its first four bytes.
        unsafe { buffer.as_ptr().cast::<u32>().read() }
    }

    fn listeners_v4() -> Option<Vec<(SocketAddr, u32)>> {
        let buffer = table(AF_INET)?;
        let count = entries(&buffer);
        let first = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        let rows: Vec<MIB_TCPROW_OWNER_PID> = rows(&buffer, count, first)?;
        Some(
            rows.into_iter()
                .filter(|row| row.dwState == MIB_TCP_STATE_LISTEN as u32)
                .map(|row| {
                    let ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                    (
                        SocketAddr::new(IpAddr::V4(ip), port(row.dwLocalPort)),
                        row.dwOwningPid,
                    )
                })
                .collect(),
        )
    }

    fn listeners_v6() -> Option<Vec<(SocketAddr, u32)>> {
        let buffer = table(AF_INET6)?;
        let count = entries(&buffer);
        let first = std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
        let rows: Vec<MIB_TCP6ROW_OWNER_PID> = rows(&buffer, count, first)?;
        Some(
            rows.into_iter()
                .filter(|row| row.dwState == MIB_TCP_STATE_LISTEN as u32)
                .map(|row| {
                    let ip = Ipv6Addr::from(row.ucLocalAddr);
                    (
                        SocketAddr::new(IpAddr::V6(ip), port(row.dwLocalPort)),
                        row.dwOwningPid,
                    )
                })
                .collect(),
        )
    }

    /// A port as the tables hold it: network order, in the low 16 bits.
    fn port(raw: u32) -> u16 {
        u16::from_be(raw as u16)
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::proc_net::{classify, listeners, owner_in, socket_address, uid_min};
    use super::*;

    fn at(address: &str) -> SocketAddr {
        address.parse().unwrap()
    }

    #[test]
    fn loopback_is_any_address_resolved_on_loopback() {
        let on = |resolved: &[&str]| on_loopback(resolved.iter().map(|address| at(address)));
        assert_eq!(on(&["127.0.0.1:9050"]), Some(vec![at("127.0.0.1:9050")]));
        assert_eq!(on(&["127.4.5.6:9150"]), Some(vec![at("127.4.5.6:9150")]));
        assert_eq!(on(&["[::1]:9050"]), Some(vec![at("[::1]:9050")]));
        assert_eq!(
            on(&["[::ffff:127.0.0.1]:9050"]),
            Some(vec![at("127.0.0.1:9050")])
        );
        // A connection to the wildcard lands on loopback.
        assert_eq!(on(&["0.0.0.0:9050"]), Some(vec![at("127.0.0.1:9050")]));
        assert_eq!(on(&["[::]:9050"]), Some(vec![at("[::1]:9050")]));
        // A name that resolves to the network and to loopback: the
        // connection may take loopback.
        assert_eq!(
            on(&["[2001:db8::7]:9050", "127.0.1.1:9050", "127.0.1.1:9050"]),
            Some(vec![at("127.0.1.1:9050")])
        );
        for elsewhere in [&["192.168.1.10:9050"][..], &["[fe80::1]:9050"], &[]] {
            assert_eq!(on(elsewhere), None, "{elsewhere:?}");
        }
    }

    /// Resolved as a connection resolves it: the numeric spellings of
    /// IPv4 and an IPv6 address without brackets are loopback, an
    /// address away from it is not, and one that does not resolve has
    /// no candidate.
    #[tokio::test]
    async fn every_spelling_of_loopback_resolves_there() {
        for written in ["127.1:9050", "2130706433:9050", "0x7f000001:9050"] {
            assert_eq!(
                loopback_addresses(written).await,
                Some(vec![at("127.0.0.1:9050")]),
                "{written}"
            );
        }
        assert_eq!(
            loopback_addresses("::1:9050").await,
            Some(vec![at("[::1]:9050")])
        );
        assert_eq!(loopback_addresses("192.168.1.10:9050").await, None);
        assert_eq!(
            loopback_addresses("tor.invalid:9050").await,
            Some(Vec::new())
        );
        assert_eq!(of(Vec::new()).await, LoopbackOwner::Unknown);
    }

    #[test]
    fn a_wildcard_listener_takes_loopback_connections() {
        let tor = at("127.0.0.1:9050");
        assert!(reaches(at("127.0.0.1:9050"), tor));
        assert!(reaches(at("0.0.0.0:9050"), tor));
        assert!(reaches(at("[::]:9050"), tor));
        assert!(reaches(at("[::ffff:127.0.0.1]:9050"), tor));
        assert!(!reaches(at("127.0.0.2:9050"), tor));
        assert!(!reaches(at("127.0.0.1:9150"), tor));
        assert!(!reaches(at("[::1]:9050"), tor));

        let six = at("[::1]:9050");
        assert!(reaches(at("[::]:9050"), six));
        assert!(!reaches(at("0.0.0.0:9050"), six));
    }

    /// Lines as a little-endian kernel writes them.
    #[cfg(target_endian = "little")]
    #[test]
    fn the_proc_tables_read_with_their_byte_order() {
        assert_eq!(socket_address("0100007F:235A"), Some(at("127.0.0.1:9050")));
        assert_eq!(socket_address("00000000:0EBD"), Some(at("0.0.0.0:3773")));
        assert_eq!(
            socket_address("00000000000000000000000001000000:235A"),
            Some(at("[::1]:9050"))
        );
        assert_eq!(
            socket_address("0000000000000000FFFF00000100007F:235A"),
            Some(at("[::ffff:127.0.0.1]:9050"))
        );
        assert_eq!(socket_address("0100007F"), None);
        assert_eq!(socket_address("0100007:235A"), None);

        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
            \x20  0: 0100007F:235A 00000000:0000 0A 00000000:00000000 00:00000000 00000000   112        0 23456 1 0000000000000000 100 0 0 10 0\n\
            \x20  1: 0100007F:235A 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1001        0 23457 1 0000000000000000 100 0 0 10 0\n\
            \x20  2: 00000000:0EBD 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 16160617 1 0000000000000000 100 0 0 10 0\n\
            \x20  3: garbage\n";
        assert_eq!(
            listeners(tcp).collect::<Vec<_>>(),
            vec![(at("127.0.0.1:9050"), 112), (at("0.0.0.0:3773"), 1000)]
        );
        let tcp6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
            \x20  0: 00000000000000000000000001000000:235A 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 17268177 2 0000000000000000 100 0 0 10 0\n";
        assert_eq!(
            listeners(tcp6).collect::<Vec<_>>(),
            vec![(at("[::1]:9050"), 1001)]
        );

        // Tor run by the system on IPv4: `localhost` could still land on
        // the IPv6 listener another account opened.
        let v4 = [at("127.0.0.1:9050")];
        assert_eq!(
            owner_in(&v4, &[tcp, tcp6], 1000, 1000),
            LoopbackOwner::System
        );
        let both = [at("127.0.0.1:9050"), at("[::1]:9050")];
        assert_eq!(
            owner_in(&both, &[tcp, tcp6], 1000, 1000),
            LoopbackOwner::OtherAccount
        );
        // Nothing found is nobody this build can name.
        assert_eq!(
            owner_in(&[at("127.0.0.1:9150")], &[tcp, tcp6], 1000, 1000),
            LoopbackOwner::Unknown
        );
    }

    #[test]
    fn accounts_are_this_one_the_system_or_another() {
        assert_eq!(classify(1000, 1000, 1000), LoopbackOwner::ThisAccount);
        assert_eq!(classify(0, 1000, 1000), LoopbackOwner::System);
        assert_eq!(classify(112, 1000, 1000), LoopbackOwner::System);
        assert_eq!(classify(999, 1000, 1000), LoopbackOwner::System);
        assert_eq!(classify(1001, 1000, 1000), LoopbackOwner::OtherAccount);
        assert_eq!(classify(65534, 1000, 1000), LoopbackOwner::OtherAccount);
        // Even where UID_MIN would put nobody below it.
        assert_eq!(classify(65534, 1000, 70000), LoopbackOwner::OtherAccount);
        assert_eq!(classify(500, 1000, 500), LoopbackOwner::OtherAccount);
        // Root running the app is this account, not the system.
        assert_eq!(classify(0, 0, 1000), LoopbackOwner::ThisAccount);
        // A computer whose people got their accounts from 500, kept past
        // a migration to a UID_MIN of 1000: running as 501, the
        // accounts below it are people too, and root alone is the
        // system.
        assert_eq!(classify(502, 501, 1000), LoopbackOwner::OtherAccount);
        assert_eq!(classify(112, 501, 1000), LoopbackOwner::OtherAccount);
        assert_eq!(classify(0, 501, 1000), LoopbackOwner::System);
        assert_eq!(classify(501, 501, 1000), LoopbackOwner::ThisAccount);
    }

    #[test]
    fn uid_min_is_read_from_login_defs() {
        let defs = "# UID_MIN 2000\n#SYS_UID_MIN 101\nSUB_UID_MIN\t100000\nUID_MIN\t\t\t 1000\nUID_MAX 60000\n";
        assert_eq!(uid_min(defs), Some(1000));
        assert_eq!(uid_min("UID_MIN 500"), Some(500));
        assert_eq!(uid_min("UID_MIN lots\n"), None);
        assert_eq!(uid_min(""), None);
    }

    #[test]
    fn many_listeners_answer_for_the_most_doubtful() {
        use LoopbackOwner::*;
        assert_eq!(LoopbackOwner::of_all([]), Unknown);
        assert_eq!(LoopbackOwner::of_all([System, ThisAccount]), ThisAccount);
        assert_eq!(LoopbackOwner::of_all([System, Unknown]), Unknown);
        assert_eq!(
            LoopbackOwner::of_all([OtherAccount, Unknown, System]),
            OtherAccount
        );
        assert!(ThisAccount.is_trusted() && System.is_trusted());
        assert!(!OtherAccount.is_trusted() && !Unknown.is_trusted());
    }

    /// Against the real tables: a socket this test opens belongs to this
    /// account where the core can tell, and to nobody it can name
    /// elsewhere. The Windows CI job runs this one.
    #[tokio::test]
    async fn a_listener_opened_here_belongs_to_this_account() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let expected = if cfg!(any(target_os = "linux", windows)) {
            LoopbackOwner::ThisAccount
        } else {
            LoopbackOwner::Unknown
        };
        let candidates = loopback_addresses(&address).await.unwrap();
        assert_eq!(of(candidates.clone()).await, expected);
        drop(listener);
        // Closed, nothing listens there any more.
        assert_eq!(of(candidates).await, LoopbackOwner::Unknown);
    }
}

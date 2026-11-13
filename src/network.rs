//! Fixed guest addressing behind a private, worker-owned routing namespace.
//! Routing slots are pre-created and pooled (AgentENV `NetworkManager` pattern):
//! a create only attaches a fresh guest namespace and installs its template's
//! rules; a release resets the slot instead of deleting it. Only the
//! operator-provisioned bridge exists outside the owned slots.
use std::{collections::BTreeSet, fs, path::{Path, PathBuf}, sync::PoisonError, time::Duration};
use crate::{model::NetworkPolicy, native::Native, process::Result, storage};

pub const GUEST: &str = "192.0.2.2";
const GATEWAY: &str = "192.0.2.1";
// A pooled routing slot this worker built: clean and free, or carrying a sandbox's guest and rules.
#[derive(Clone, Copy, PartialEq)]
pub enum SlotState { Ready, Attached }
// Confirm a link name is absent from the current network namespace; unreadable inventory is not proof
// of absence.
fn link_absent(name: &str) -> bool {
    fs::read_to_string("/proc/net/dev").is_ok_and(|v| !v.lines().any(|l| l.split_once(':').is_some_and(|(n,_)| n.trim() == name)))
}
impl Native {
    // Derive the stable guest namespace name from the worker root and sandbox ID.
    pub fn guest_name(&self, id: &str) -> String {
        let hash = storage::digest(format!("{}:{id}", self.config.root).as_bytes());
        format!("{}g-{}", self.network_prefix(), &hash[..20])
    }
    // Derive a pooled slot's routing namespace and host link names from the worker root and slot index.
    pub fn slot_names(&self, index: usize) -> (String, String) {
        (format!("{}s-{index}", self.network_prefix()), format!("sb{}{index:03x}", &storage::digest(self.config.root.as_bytes())[..10]))
    }
    // Derive the namespace-name prefix reserved for this worker root.
    fn network_prefix(&self) -> String { format!("sb-{}-", &storage::digest(self.config.root.as_bytes())[..16]) }
    // Return the durable ownership directory of one pooled slot; it exists before any slot resource.
    fn slot_dir(&self, index: usize) -> PathBuf { self.root().join("slots").join(index.to_string()) }
    // List the slot indexes this worker root durably owns. Any other entry in the slot directory is
    // unknown state and fails closed.
    fn owned_slots(&self) -> Result<Vec<usize>> {
        let mut found = Vec::new();
        for entry in fs::read_dir(self.root().join("slots")).map_err(|_| "network_scan_failed")? {
            let name = entry.map_err(|_| "network_scan_failed")?.file_name();
            let index = name.to_str().and_then(|n| n.parse::<usize>().ok().filter(|i| *i < 256 && i.to_string() == n));
            found.push(index.ok_or("untracked_network_state")?);
        }
        Ok(found)
    }
    // Check recorded sandbox guest namespaces and pooled slots for ownership markers. Reject extra
    // namespace names under this worker's prefix rather than adopting unknown state.
    pub fn verify_network_names<'a>(&self, ids: impl Iterator<Item = &'a str>) -> Result<()> {
        let mut expected = BTreeSet::new();
        for id in ids {
            expected.insert(self.guest_name(id));
            if !self.network_absent(id) && !self.private(id).join("network-owned").exists() { return Err("untracked_network_state"); }
        }
        for index in self.owned_slots()? { expected.insert(self.slot_names(index).0); }
        if Path::new("/run/netns").exists() {
            for entry in fs::read_dir("/run/netns").map_err(|_| "network_scan_failed")? {
                let name = entry.map_err(|_| "network_scan_failed")?.file_name().to_string_lossy().into_owned();
                if name.starts_with(&self.network_prefix()) && !expected.contains(&name) { return Err("untracked_network_state"); }
            }
        }
        Ok(())
    }
    // Confirm that the sandbox's guest namespace pin is absent; its slot belongs to the pool.
    pub fn network_absent(&self, id: &str) -> bool { !Path::new("/run/netns").join(self.guest_name(id)).exists() }
    // Require a template's TCP destinations and service ports to be valid subsets of operator permissions;
    // isolation needs none.
    pub fn network_policy(&self, policy: &NetworkPolicy) -> Result<()> {
        if let NetworkPolicy::TcpAllowlist { egress, service_ports } = policy {
            let config = self.config.network.as_ref().ok_or("network_disabled")?;
            if !policy.valid() || !egress.iter().all(|e| config.egress.contains(e))
                || !service_ports.iter().all(|p| config.service_ports.contains(p)) { return Err("network_policy_not_authorized"); }
        }
        Ok(())
    }
    // Run the verified ip tool inside one named namespace.
    fn ip_in(&self, namespace: &str, args: &[&str]) -> Result<()> {
        let mut all = vec!["-n".to_owned(), namespace.to_owned()];
        all.extend(args.iter().map(|s| s.to_string()));
        self.command("ip", all)
    }
    // Return the pin path of a pooled slot's routing namespace, where the app proxy opens its
    // connections to the guest.
    pub fn slot_namespace(&self, index: usize) -> PathBuf { Path::new("/run/netns").join(self.slot_names(index).0) }
    // Run one of this worker's own internal helpers inside a named namespace.
    fn helper_in(&self, namespace: &str, helper: &str) -> Result<()> {
        self.command("ip", vec!["netns".into(), "exec".into(), namespace.into(), format!("/proc/{}/exe", std::process::id()), helper.into()])
    }
    // Load an nftables file inside a named namespace as one atomic transaction.
    fn nft_in(&self, namespace: &str, file: &Path) -> Result<()> {
        self.command("ip", vec!["netns".into(), "exec".into(), namespace.into(), self.tool("nft")?.into(), "-f".into(), file.display().to_string()])
            .map_err(|_| "slot_firewall_failed")
    }
    // Pre-create one pooled routing slot: durably mark ownership, then build its namespace (IPv6 off,
    // forwarding on), the uplink veth with its pool address, a default-deny filter table and the
    // address translation, and only then attach the host link to the operator bridge and bring it up.
    // No guest is attached yet. Partial state is left for destroy_slot.
    fn create_slot(&self, index: usize) -> Result<()> {
        let config = self.config.network.as_ref().ok_or("network_disabled")?;
        let address = config.addresses.get(index).ok_or("network_slot_missing")?;
        let (slot, link) = self.slot_names(index);
        let dir = self.slot_dir(index);
        storage::exclusive_private_dir(&dir).map_err(|_| "network_ownership_failed")?;
        fs::File::open(self.root().join("slots")).and_then(|f| f.sync_all()).map_err(|_| "network_ownership_failed")?;
        self.command("ip", vec!["netns".into(), "add".into(), slot.clone()]).map_err(|_| "slot_namespace_create_failed")?;
        self.helper_in(&slot, "internal-forward")?;
        self.ip_in(&slot, &["link", "add", "uplink", "type", "veth", "peer", "name", &link])?;
        self.ip_in(&slot, &["addr", "add", &format!("{address}/{}", config.prefix), "dev", "uplink"])?;
        // Routing/NAT/filter state is exclusively in the slot, never global. The
        // filter chains drop everything until a template's rules are added.
        let base = format!("table inet sandbox {{\nchain input {{ type filter hook input priority 0; policy drop; }}\n\
            chain output {{ type filter hook output priority 0; policy drop; }}\nchain forward {{ type filter hook forward priority 0; policy drop; }}\n}}\n\
            table ip sandbox_nat {{ chain postrouting {{ type nat hook postrouting priority 100; policy accept; ip saddr {GUEST} oifname uplink snat to {address}\n}}\n}}\n");
        fs::write(dir.join("base.nft"), base).map_err(|_| "network_policy_write_failed")?;
        self.nft_in(&slot, &dir.join("base.nft"))?;
        self.ip_in(&slot, &["link", "set", &link, "netns", &std::process::id().to_string()])?;
        self.command("ip", vec!["link".into(), "set".into(), link.clone(), "master".into(), config.bridge.clone()])?;
        self.ip_in(&slot, &["link", "set", "uplink", "up"])?;
        self.ip_in(&slot, &["route", "add", "default", "via", &config.gateway.to_string()])?;
        self.command("ip", vec!["link".into(), "set".into(), link, "up".into()])
    }
    // Remove one pooled slot this worker owns: delete its namespace pin, wait for the kernel to destroy
    // its links (the host link goes with them), then drop the ownership directory. An absent slot
    // succeeds; incomplete teardown keeps ownership and fails.
    fn destroy_slot(&self, index: usize) -> Result<()> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner).remove(&index);
        let (slot, link) = self.slot_names(index);
        if Path::new("/run/netns").join(&slot).exists() { self.command("ip", vec!["netns".into(), "delete".into(), slot])?; }
        let start = std::time::Instant::now();
        while !link_absent(&link) {
            if start.elapsed() >= Duration::from_secs(5) { return Err("network_cleanup_incomplete"); }
            std::thread::sleep(Duration::from_millis(20));
        }
        storage::remove_private(&self.slot_dir(index))?;
        fs::File::open(self.root().join("slots")).and_then(|f| f.sync_all()).map_err(|_| "network_ownership_failed")
    }
    // Rebuild the slot pool at worker start, after sandbox reconciliation: remove every slot left by an
    // earlier worker (never adopt it), then pre-create the first `count` slots that no remaining
    // reservation holds. A slot that fails to build is removed and built lazily at create instead; a
    // slot that cannot be removed stops startup.
    pub fn start_slot_pool(&self, count: usize, held: &BTreeSet<usize>) -> Result<()> {
        self.remove_slot_pool()?;
        let Some(config) = self.config.network.as_ref() else { return Ok(()); };
        for index in (0..count.min(config.addresses.len())).filter(|i| !held.contains(i)) {
            match self.create_slot(index) {
                Ok(()) => { self.slots.lock().unwrap_or_else(PoisonError::into_inner).insert(index, SlotState::Ready); }
                Err(_) => self.destroy_slot(index)?,
            }
        }
        Ok(())
    }
    // Remove every pooled slot this worker owns (startup and shutdown, when no guest uses them).
    pub fn remove_slot_pool(&self) -> Result<()> {
        for index in self.owned_slots()? { self.destroy_slot(index)?; }
        Ok(())
    }
    // Claim a pooled slot for a new guest (AgentENV allocate): a ready slot is reused as it is; a missing
    // or unknown one is built now, after removing any leftover. From here the slot counts as attached, so
    // its release always resets it.
    fn claim_slot(&self, index: usize) -> Result<()> {
        let known = self.slots.lock().unwrap_or_else(PoisonError::into_inner).get(&index).copied();
        match known {
            Some(SlotState::Ready) => {}
            Some(SlotState::Attached) => return Err("network_slot_busy"),
            None => {
                self.destroy_slot(index)?;
                if let Err(e) = self.create_slot(index) { let _ = self.destroy_slot(index); return Err(e); }
            }
        }
        self.slots.lock().unwrap_or_else(PoisonError::into_inner).insert(index, SlotState::Attached);
        Ok(())
    }
    // Return a slot to the pool once its sandbox is drained (AgentENV release): delete the slot's end of
    // the guest veth pair (which removes the guest's end at once), flush the template rules back to the
    // default-deny base and clear connection tracking. A clean slot needs nothing. A slot that cannot be
    // reset, or whose state is unknown, is removed instead and rebuilt lazily later.
    fn release_slot(&self, index: usize) -> Result<()> {
        let known = self.slots.lock().unwrap_or_else(PoisonError::into_inner).get(&index).copied();
        let (slot, _) = self.slot_names(index);
        match known {
            Some(SlotState::Ready) => return Ok(()),
            None => return self.destroy_slot(index),
            Some(SlotState::Attached) => {}
        }
        let reset = (|| {
            // An already absent link fails this step harmlessly; the reset helper
            // below verifies that no guest link remains.
            let _ = self.ip_in(&slot, &["link", "delete", "inside"]);
            self.command("ip", vec!["netns".into(), "exec".into(), slot.clone(), self.tool("nft")?.into(), "flush".into(), "table".into(), "inet".into(), "sandbox".into()])?;
            self.helper_in(&slot, "internal-slot-reset")
        })();
        match reset {
            Ok(()) => { self.slots.lock().unwrap_or_else(PoisonError::into_inner).insert(index, SlotState::Ready); Ok(()) }
            Err(_) => self.destroy_slot(index),
        }
    }
    // Create the sandbox's private guest network namespace with loopback up and IPv6 off. An isolated
    // policy stops there (loopback only, no links). For an approved TCP policy, claim the sandbox's pooled
    // slot, atomically replace its rules with the template's (over the default-deny base), then connect
    // the guest with a veth pair and bring it up. Caller-owned cleanup handles partial setup failures.
    pub fn prepare_network(&self, id: &str, policy: &NetworkPolicy, index: Option<usize>) -> Result<()> {
        self.network_policy(policy)?;
        if !self.network_absent(id) { return Err("network_name_conflict"); }
        let guest = self.guest_name(id);
        // Durable record/slot exists before this exclusive ownership marker or any
        // resource. The root lock excludes competing writers of this name prefix.
        let marker = self.private(id).join("network-owned");
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&marker)
            .and_then(|f| f.sync_all()).map_err(|_| "network_ownership_failed")?;
        fs::File::open(self.private(id)).and_then(|f| f.sync_all()).map_err(|_| "network_ownership_failed")?;
        // runc checkpoints always treat the network namespace as empty, so CRIU
        // restores no links or addresses. A worker-created namespace (passed by
        // path) keeps loopback up for restored loopback connections.
        self.command("ip", vec!["netns".into(), "add".into(), guest.clone()]).map_err(|_| "guest_namespace_create_failed")?;
        self.helper_in(&guest, "internal-guest-network")?;
        self.ip_in(&guest, &["link", "set", "lo", "up"])?;
        let NetworkPolicy::TcpAllowlist { egress, service_ports } = policy else { return Ok(()); };
        let index = index.ok_or("network_slot_missing")?;
        self.claim_slot(index)?;
        let (slot, _) = self.slot_names(index);
        // PMTU errors may come from any router, but must quote an existing
        // authorized TCP flow. Never accept arbitrary ICMP or all RELATED traffic.
        let pmtu = |e: &crate::model::TcpDestination| format!("ip daddr {GUEST} icmp type destination-unreachable icmp code frag-needed ct state related ct original protocol tcp ct original ip saddr {GUEST} ct original ip daddr {} ct original proto-dst {} counter accept", e.ip, e.port);
        // One transaction: drop any previous rules, then add this template's.
        let mut rules = format!("flush table inet sandbox\nadd rule inet sandbox input iifname inside ip saddr {GUEST} ip daddr {GATEWAY} meta l4proto tcp ct state established accept\n");
        for port in service_ports { rules.push_str(&format!("add rule inet sandbox output oifname inside ip saddr {GATEWAY} ip daddr {GUEST} tcp dport {port} accept\n")); }
        for e in egress { rules.push_str(&format!("add rule inet sandbox output oifname inside {}\n", pmtu(e))); }
        for e in egress {
            rules.push_str(&format!("add rule inet sandbox forward iifname inside oifname uplink ip saddr {GUEST} ip daddr {} tcp dport {} ct state new,established accept\n", e.ip, e.port));
            rules.push_str(&format!("add rule inet sandbox forward iifname uplink oifname inside ip saddr {} ip daddr {GUEST} tcp sport {} ct state established accept\n", e.ip, e.port));
            rules.push_str(&format!("add rule inet sandbox forward iifname uplink oifname inside {}\n", pmtu(e)));
        }
        let file = self.private(id).join("network.nft");
        fs::write(&file, rules).map_err(|_| "network_policy_write_failed")?;
        self.nft_in(&slot, &file)?;
        self.ip_in(&slot, &["link", "add", "inside", "type", "veth", "peer", "name", "eth0", "netns", &guest])?;
        self.ip_in(&slot, &["addr", "add", &format!("{GATEWAY}/30"), "dev", "inside"])?;
        self.ip_in(&guest, &["addr", "add", &format!("{GUEST}/30"), "dev", "eth0"])?;
        // No guest link is up and no untrusted process exists until the rules succeed.
        self.ip_in(&slot, &["link", "set", "inside", "up"])?;
        self.ip_in(&guest, &["link", "set", "eth0", "up"])?;
        self.ip_in(&guest, &["route", "add", "default", "via", GATEWAY])
    }
    // Remove only network state backed by this sandbox's ownership marker: return its pooled slot to the
    // pool (reset, not deleted) and delete its guest namespace pin. Unknown state or incomplete cleanup
    // remains an error.
    pub fn cleanup_network(&self, id: &str, index: Option<usize>) -> Result<()> {
        if !self.private(id).join("network-owned").exists() {
            return if self.network_absent(id) { Ok(()) } else { Err("untracked_network_state") };
        }
        // Called after helper and workload drainage, so no guest traffic remains.
        if let Some(index) = index.filter(|_| self.config.network.is_some()) { self.release_slot(index)?; }
        let guest = self.guest_name(id);
        if Path::new("/run/netns").join(&guest).exists() { self.command("ip", vec!["netns".into(), "delete".into(), guest])?; }
        if self.network_absent(id) { Ok(()) } else { Err("network_cleanup_incomplete") }
    }
}

// Disable IPv6 in the current namespace and enable IPv4 forwarding only for a routing slot. This runs
// in a fresh, tracked helper process, never a pooled worker thread.
pub fn forward_helper(forward: bool) -> Result<()> {
    for name in ["all", "default"] {
        fs::write(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"), "1").map_err(|_| "namespace_ipv6_disable_failed")?;
    }
    if forward { fs::write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|_| "slot_forwarding_failed")?; }
    Ok(())
}
// Inside a routing slot being returned to the pool: require that no guest link remains, then flush all
// connection-tracking entries through netlink (a delete request with no tuple), so the next sandbox
// inherits no flow or address-translation state. This runs in a fresh, tracked helper process, never
// a pooled worker thread.
pub fn slot_reset_helper() -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    if !link_absent("inside") { return Err("slot_guest_link_remains"); }
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_NETFILTER) };
    if fd < 0 { return Err("conntrack_flush_failed"); }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // struct nlmsghdr, then struct nfgenmsg (AF_UNSPEC, version 0, resource 0).
    // Type: NFNL_SUBSYS_CTNETLINK (1) << 8 | IPCTNL_MSG_CT_DELETE (2).
    let mut message = [0u8; 20];
    message[0..4].copy_from_slice(&20u32.to_ne_bytes());
    message[4..6].copy_from_slice(&(1u16 << 8 | 2).to_ne_bytes());
    message[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16).to_ne_bytes());
    message[8..12].copy_from_slice(&1u32.to_ne_bytes());
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let wait = libc::timeval { tv_sec: 5, tv_usec: 0 };
    let ok = unsafe {
        libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&wait as *const libc::timeval).cast(), std::mem::size_of::<libc::timeval>() as libc::socklen_t) == 0
            && libc::sendto(fd.as_raw_fd(), message.as_ptr().cast(), message.len(), 0, (&kernel as *const libc::sockaddr_nl).cast(), std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t) == message.len() as isize
    };
    if !ok { return Err("conntrack_flush_failed"); }
    // The acknowledgement is an NLMSG_ERROR message for sequence 1 with error code 0.
    let mut reply = [0u8; 4096];
    let n = unsafe { libc::recv(fd.as_raw_fd(), reply.as_mut_ptr().cast(), reply.len(), 0) };
    let field = |at: usize| u32::from_ne_bytes(reply[at..at + 4].try_into().unwrap());
    if n < 20 || u16::from_ne_bytes([reply[4], reply[5]]) as i32 != libc::NLMSG_ERROR || field(8) != 1 || field(16) != 0 { return Err("conntrack_flush_failed"); }
    Ok(())
}

//! Fixed guest addressing behind a private, worker-owned routing namespace.
//! Only the operator-provisioned bridge exists outside the owned slot.
use std::{fs, path::Path, time::Duration};
use crate::{model::{NetworkPolicy, HttpRequest, HttpOutput}, native::Native, process::{self, Result}, storage};

pub const GUEST: &str = "192.0.2.2";
const GATEWAY: &str = "192.0.2.1";
fn link_absent(name: &str) -> bool {
    fs::read_to_string("/proc/net/dev").is_ok_and(|v| !v.lines().any(|l| l.split_once(':').is_some_and(|(n,_)| n.trim() == name)))
}
impl Native {
    pub fn network_names(&self, id: &str) -> (String, String, String) {
        let hash = storage::digest(format!("{}:{id}", self.config.root).as_bytes());
        let prefix = self.network_prefix();
        (format!("{prefix}g-{}", &hash[..20]), format!("{prefix}s-{}", &hash[..20]), format!("sb{}", &hash[..12]))
    }
    fn network_prefix(&self) -> String { format!("sb-{}-", &storage::digest(self.config.root.as_bytes())[..16]) }
    pub fn verify_network_names<'a>(&self, ids: impl Iterator<Item = &'a str>) -> Result<()> {
        let mut expected = std::collections::BTreeSet::new();
        for id in ids {
            let (guest, slot, _) = self.network_names(id);
            expected.insert(guest); expected.insert(slot);
            if !self.network_absent(id) && !self.private(id).join("network-owned").exists() { return Err("untracked_network_state"); }
        }
        if Path::new("/run/netns").exists() {
            for entry in fs::read_dir("/run/netns").map_err(|_| "network_scan_failed")? {
                let name = entry.map_err(|_| "network_scan_failed")?.file_name().to_string_lossy().into_owned();
                if name.starts_with(&self.network_prefix()) && !expected.contains(&name) { return Err("untracked_network_state"); }
            }
        }
        Ok(())
    }
    pub fn network_absent(&self, id: &str) -> bool {
        let (guest, slot, link) = self.network_names(id);
        !Path::new("/run/netns").join(guest).exists() && !Path::new("/run/netns").join(slot).exists()
            && link_absent(&link)
    }
    pub fn network_policy(&self, policy: &NetworkPolicy) -> Result<()> {
        if let NetworkPolicy::TcpAllowlist { egress, service_ports } = policy {
            let config = self.config.network.as_ref().ok_or("network_disabled")?;
            if !policy.valid() || !egress.iter().all(|e| config.egress.contains(e))
                || !service_ports.iter().all(|p| config.service_ports.contains(p)) { return Err("network_policy_not_authorized"); }
        }
        Ok(())
    }
    pub fn prepare_network(&self, id: &str, policy: &NetworkPolicy, index: Option<usize>) -> Result<()> {
        self.network_policy(policy)?;
        let NetworkPolicy::TcpAllowlist { egress, service_ports } = policy else { return Ok(()); };
        let config = self.config.network.as_ref().ok_or("network_disabled")?;
        let address = config.addresses.get(index.ok_or("network_slot_missing")?).ok_or("network_slot_missing")?;
        if !self.network_absent(id) { return Err("network_name_conflict"); }
        let (guest, slot, link) = self.network_names(id);
        // Durable record/slot exists before this exclusive ownership marker or any
        // resource. The root lock excludes competing writers of this name prefix.
        let marker = self.private(id).join("network-owned");
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&marker)
            .and_then(|f| f.sync_all()).map_err(|_| "network_ownership_failed")?;
        fs::File::open(self.private(id)).and_then(|f| f.sync_all()).map_err(|_| "network_ownership_failed")?;
        let ip = |args: Vec<String>| self.command("ip", args);
        let ns = |name: &str, args: &[&str]| {
            let mut v = vec!["-n".into(), name.into()]; v.extend(args.iter().map(|s| s.to_string())); ip(v)
        };
        ip(vec!["netns".into(), "add".into(), slot.clone()]).map_err(|_| "slot_namespace_create_failed")?;
        ip(vec!["netns".into(), "add".into(), guest.clone()]).map_err(|_| "guest_namespace_create_failed")?;
        for (name, mode) in [(&slot, "internal-forward"), (&guest, "internal-guest-network")] {
            ip(vec!["netns".into(), "exec".into(), name.clone(), format!("/proc/{}/exe", std::process::id()), mode.into()])?;
        }
        ns(&slot, &["link", "add", "inside", "type", "veth", "peer", "name", "eth0", "netns", &guest])?;
        ns(&slot, &["addr", "add", &format!("{GATEWAY}/30"), "dev", "inside"])?;
        ns(&guest, &["addr", "add", &format!("{GUEST}/30"), "dev", "eth0"])?;
        ns(&slot, &["link", "add", "uplink", "type", "veth", "peer", "name", &link])?;
        ns(&slot, &["addr", "add", &format!("{address}/{}", config.prefix), "dev", "uplink"])?;
        // PMTU errors may come from any router, but must quote an existing
        // authorized TCP flow. Never accept arbitrary ICMP or all RELATED traffic.
        let pmtu = |e: &crate::model::TcpDestination| format!("ip daddr {GUEST} icmp type destination-unreachable icmp code frag-needed ct state related ct original protocol tcp ct original ip saddr {GUEST} ct original ip daddr {} ct original proto-dst {} counter accept", e.ip, e.port);
        // Routing/NAT/filter state is exclusively in the slot, never global.
        let mut rules = String::from("table inet sandbox {\nchain input { type filter hook input priority 0; policy drop;\n");
        rules.push_str(&format!("iifname inside ip saddr {GUEST} ip daddr {GATEWAY} meta l4proto tcp ct state established accept\n}}\nchain output {{ type filter hook output priority 0; policy drop;\n"));
        for port in service_ports { rules.push_str(&format!("oifname inside ip saddr {GATEWAY} ip daddr {GUEST} tcp dport {port} accept\n")); }
        for e in egress { rules.push_str(&format!("oifname inside {}\n", pmtu(e))); }
        rules.push_str("}\nchain forward { type filter hook forward priority 0; policy drop;\n");
        for e in egress {
            rules.push_str(&format!("iifname inside oifname uplink ip saddr {GUEST} ip daddr {} tcp dport {} ct state new,established accept\n", e.ip, e.port));
            rules.push_str(&format!("iifname uplink oifname inside ip saddr {} ip daddr {GUEST} tcp sport {} ct state established accept\n", e.ip, e.port));
            rules.push_str(&format!("iifname uplink oifname inside {}\n", pmtu(e)));
        }
        rules.push_str(&format!("}}\n}}\ntable ip sandbox_nat {{ chain postrouting {{ type nat hook postrouting priority 100; policy accept; ip saddr {GUEST} oifname uplink snat to {address}\n}}\n}}\n"));
        let file = self.private(id).join("network.nft");
        fs::write(&file, rules).map_err(|_| "network_policy_write_failed")?;
        ip(vec!["netns".into(), "exec".into(), slot.clone(), self.tool("nft")?.into(), "-f".into(), file.display().to_string()]).map_err(|_| "slot_firewall_failed")?;
        // No links are up and no untrusted process exists until filters succeed.
        ns(&slot, &["link", "set", &link, "netns", &std::process::id().to_string()])?;
        ip(vec!["link".into(), "set".into(), link.clone(), "master".into(), config.bridge.clone()])?;
        for (name, device) in [(&slot, "inside"), (&slot, "uplink"), (&guest, "eth0"), (&guest, "lo")] { ns(name, &["link", "set", device, "up"])?; }
        ns(&guest, &["route", "add", "default", "via", GATEWAY])?;
        ns(&slot, &["route", "add", "default", "via", &config.gateway.to_string()])?;
        ip(vec!["link".into(), "set".into(), link, "up".into()])
    }
    pub fn cleanup_network(&self, id: &str) -> Result<()> {
        if !self.private(id).join("network-owned").exists() {
            return if self.network_absent(id) { Ok(()) } else { Err("untracked_network_state") };
        }
        let (guest, slot, link) = self.network_names(id);
        // Called after helper and workload drainage. Namespace destruction removes
        // the peer links and its private rules/routes; failures retain ownership.
        for name in [guest, slot] {
            if Path::new("/run/netns").join(&name).exists() { self.command("ip", vec!["netns".into(), "delete".into(), name])?; }
        }
        let start = std::time::Instant::now();
        while !link_absent(&link) || !self.network_absent(id) {
            if start.elapsed() >= Duration::from_secs(5) { return Err("network_cleanup_incomplete"); }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }
    pub fn capture_network_ready(&self, id: &str, policy: Option<&NetworkPolicy>) -> Result<()> {
        if matches!(policy, Some(NetworkPolicy::TcpAllowlist { .. })) {
            let (guest, _, _) = self.network_names(id);
            self.command("ip", vec!["netns".into(), "exec".into(), guest, format!("/proc/{}/exe", std::process::id()), "internal-tcp-check".into()])
                .map_err(|_| "capture_requires_quiescent_tcp")?;
        }
        Ok(())
    }
    pub fn application_http(&self, id: &str, request: &HttpRequest, policy: &NetworkPolicy, remaining_ms: u64) -> Result<HttpOutput> {
        self.network_policy(policy)?;
        if !matches!(policy, NetworkPolicy::TcpAllowlist { service_ports, .. } if service_ports.contains(&request.port)) { return Err("service_port_not_authorized"); }
        let file = self.private(id).join("http.json");
        let mut request = request.clone();
        request.timeout_ms = request.timeout_ms.min(remaining_ms.max(1));
        process::atomic_json(&file, &request)?;
        let (_, slot, _) = self.network_names(id);
        let output = self.helpers.run(self.tool("ip")?, &[
            "netns".into(), "exec".into(), slot, format!("/proc/{}/exe", std::process::id()), "internal-http".into(), file.display().to_string()],
            Duration::from_millis(request.timeout_ms + 1000), request.max_response_bytes as usize * 6 + 8192, false, &self.search_path);
        let _ = fs::remove_file(file);
        let out = output?;
        if out.interrupted || out.exit_code != Some(0) { return Err("application_http_failed_or_bounded"); }
        serde_json::from_str(&out.stdout).map_err(|_| "application_http_invalid_result")
    }
}

// This mode runs in a fresh, tracked helper process, never a pooled worker thread.
pub fn forward_helper(forward: bool) -> Result<()> {
    for name in ["all", "default"] {
        fs::write(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"), "1").map_err(|_| "namespace_ipv6_disable_failed")?;
    }
    if forward { fs::write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|_| "slot_forwarding_failed")?; }
    Ok(())
}
pub fn tcp_check_helper() -> Result<()> {
    use std::io::Read;
    let mut text = String::new();
    fs::File::open("/proc/net/tcp").map_err(|_| "tcp_state_unavailable")?.take(4194305).read_to_string(&mut text).map_err(|_| "tcp_state_unavailable")?;
    if text.len() > 4194304 || text.lines().skip(1).any(|l| !matches!(l.split_whitespace().nth(3), Some("0A" | "06" | "07"))) { return Err("capture_requires_quiescent_tcp"); }
    Ok(())
}
pub fn http_helper(path: &Path) -> Result<()> {
    let request: HttpRequest = storage::read_json(path, 65536)?;
    if !request.valid() { return Err("invalid_http_request"); }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| "http_runtime_failed")?;
    let output = runtime.block_on(async {
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).http1_only()
            .timeout(Duration::from_millis(request.timeout_ms)).pool_max_idle_per_host(0).build().map_err(|_| "http_client_failed")?;
        // Construct authority, then set path/query: no caller-provided host, URL,
        // redirect, proxy, bearer or inherited environment can select a destination.
        let mut url = reqwest::Url::parse(&format!("http://{GUEST}:{}/", request.port)).map_err(|_| "http_url_failed")?;
        let (path, query) = request.path.split_once('?').map_or((request.path.as_str(), None), |(p,q)| (p, Some(q)));
        url.set_path(path); url.set_query(query);
        let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|_| "invalid_http_method")?;
        let mut call = client.request(method, url).body(request.body);
        for (key, value) in request.headers { call = call.header(key, value); }
        let mut response = call.send().await.map_err(|_| "http_request_failed")?;
        if response.headers().iter().map(|(k,v)| k.as_str().len() + v.len()).sum::<usize>() > 16384
            || response.content_length().is_some_and(|n| n > request.max_response_bytes) { return Err("http_response_limit"); }
        let status = response.status().as_u16();
        let content_type = response.headers().get("content-type").map(|v| v.to_str().map(str::to_owned)).transpose().map_err(|_| "http_invalid_header")?;
        if content_type.as_ref().is_some_and(|v| v.len() > 256) { return Err("http_response_header_limit"); }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "http_response_failed")? {
            if body.len() + chunk.len() > request.max_response_bytes as usize { return Err("http_response_limit"); }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpOutput { status, content_type, body: String::from_utf8(body).map_err(|_| "http_response_not_utf8")? })
    })?;
    println!("{}", serde_json::to_string(&output).map_err(|_| "http_encode_failed")?);
    Ok(())
}

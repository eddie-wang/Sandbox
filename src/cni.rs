//! Standalone CNI inside each private routing slot; never in the worker's network namespace.
//! Fresh Rust integration of libcni v1.3.0 api.go (AddNetworkList, DelNetworkList, cacheAdd)
//! and plugins v1.1.1 ptp.go (cmdAdd/cmdDel): ordered results, persisted intent, reverse DEL.
//! Only the fixed ptp + static chain is supported; IP allocation and nft policy stay with the worker.
use std::{fs, os::unix::process::CommandExt, path::Path, process::{Command, Stdio}, time::Duration};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{native::Native, network::{GATEWAY, GUEST}, process::{self, Result}, storage};

const VERSION: &str = "1.0.0";
const IFNAME: &str = "eth0";
const LIMIT: usize = 65536;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plugin { config: Value, attempted: bool, result: Option<Value> }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Attachment { version: u32, id: String, slot: usize, netns: String, plugins: Vec<Plugin> }

// Replace this helper with a verified plugin, supplying only CNI's environment and private input.
// ADD/CHECK/DEL callers enter the routing slot and track descendants; read-only VERSION queries
// instead use the caller's namespace without a helper group or configuration input.
pub fn exec(args: &[std::ffi::OsString]) -> Result<()> {
    let [plugin, path, operation, id, netns, input] = args else { return Err("cni_helper_usage") };
    if !["ADD", "DEL", "CHECK", "VERSION"].iter().any(|v| operation == *v) { return Err("cni_helper_usage"); }
    let stdin = if input == "-" { Stdio::null() } else { Stdio::from(fs::File::open(input).map_err(|_| "cni_input_unavailable")?) };
    let _ = Command::new(plugin).env_clear().env("PATH", path).env("LANG", "C")
        .env("CNI_COMMAND", operation).env("CNI_CONTAINERID", id).env("CNI_NETNS", netns)
        .env("CNI_IFNAME", IFNAME).env("CNI_PATH", path).env("CNI_ARGS", "")
        .stdin(stdin).exec();
    Err("cni_exec_failed")
}

// Query a verified plugin's supported protocol versions without touching links or allocation state.
pub fn supports_version(plugin: &str, path: &str) -> bool {
    let args = ["internal-cni", plugin, path, "VERSION", "", "", "-"].map(str::to_owned);
    process::inspect("/proc/self/exe", &args, path).ok().filter(|o| !o.interrupted && o.exit_code == Some(0))
        .and_then(|o| serde_json::from_str::<Value>(&o.stdout).ok())
        .is_some_and(|v| v["supportedVersions"].as_array().is_some_and(|versions| versions.iter().any(|v| v == VERSION)))
}

impl Native {
    // Invoke a plugin with bounded output/time and tracked descendants in its slot, using the cached
    // configuration plus the previous chain result. A vanished guest is an empty netns on DEL.
    fn cni_invoke(&self, attachment: &Attachment, config: &Value, previous: Option<&Value>, operation: &str) -> Result<Value> {
        let mut input = config.clone();
        if let Some(previous) = previous { input["prevResult"] = previous.clone(); }
        let file = self.private(&attachment.id).join("cni-input.json");
        process::atomic_json(&file, &input)?;
        let netns = if operation == "DEL" && !Path::new(&attachment.netns).exists() { "" } else { &attachment.netns };
        let plugin = config["type"].as_str().filter(|s| *s == "ptp").ok_or("cni_cache_invalid")?;
        let args = vec!["internal-cni".into(), self.tool(plugin)?.into(), self.search_path.clone(), operation.into(),
            attachment.id.clone(), netns.into(), file.display().to_string()];
        let out = self.helpers.run(&format!("/proc/{}/exe", std::process::id()), &args,
            Duration::from_secs(self.config.command_timeout_seconds), LIMIT, false, &self.search_path, Some(&self.slot_namespace(attachment.slot)))?;
        if out.interrupted || out.exit_code != Some(0) {
            process::log_failure(plugin, "cni_failed", out.exit_code, &out.stderr);
            return Err("cni_failed");
        }
        if operation != "ADD" { return Ok(Value::Null); }
        let result: Value = serde_json::from_str(&out.stdout).map_err(|_| "cni_result_invalid")?;
        if result["cniVersion"] != VERSION { return Err("cni_result_invalid"); }
        Ok(result)
    }
    // Persist each ADD intent before execution and each result before advancing, as libcni caches
    // attachments. On every partial failure, DEL even the failed plugin; cleanup retries any failure.
    pub fn cni_add(&self, id: &str, slot: usize) -> Result<String> {
        let mtu = self.config.network.as_ref().ok_or("network_disabled")?.mtu;
        let path = self.private(id).join("cni.json");
        if path.exists() { return Err("cni_attachment_exists"); }
        let mut attachment = Attachment { version: 1, id: id.into(), slot,
            netns: format!("/run/netns/{}", self.guest_name(id)), plugins: vec![Plugin {
                config: json!({"cniVersion": VERSION, "name": "sandbox-slot", "type": "ptp", "mtu": mtu, "ipMasq": false,
                    "ipam": {"type": "static", "addresses": [{"address": format!("{GUEST}/30"), "gateway": GATEWAY}],
                        "routes": [{"dst": "0.0.0.0/0"}]}}), attempted: false, result: None }] };
        process::atomic_json(&path, &attachment)?;
        let result = (|| {
            let mut previous = None;
            for index in 0..attachment.plugins.len() {
                attachment.plugins[index].attempted = true;
                process::atomic_json(&path, &attachment)?;
                let result = self.cni_invoke(&attachment, &attachment.plugins[index].config, previous.as_ref(), "ADD")?;
                attachment.plugins[index].result = Some(result.clone());
                process::atomic_json(&path, &attachment)?;
                previous = Some(result);
            }
            let result = previous.ok_or("cni_result_invalid")?;
            let host = self.cni_validate(&attachment, &result, mtu)?;
            for plugin in &attachment.plugins { self.cni_invoke(&attachment, &plugin.config, Some(&result), "CHECK")?; }
            Ok(host)
        })();
        if result.is_err() { self.cni_del(id, slot)?; }
        result
    }
    // Require ptp's fixed guest address/name and a safe host interface name, then check both link MTUs.
    // ptp v1.1.1 uses a random host name/MAC; CRIU treats this supplied netns as external and empty.
    fn cni_validate(&self, attachment: &Attachment, result: &Value, mtu: u32) -> Result<String> {
        let interfaces = result["interfaces"].as_array().filter(|v| v.len() == 2).ok_or("cni_result_invalid")?;
        let host = interfaces[0]["name"].as_str().filter(|s| !s.is_empty() && s.len() <= 15 && s.bytes().all(|b| b.is_ascii_alphanumeric()))
            .filter(|s| !["lo", "uplink", IFNAME].contains(s)).ok_or("cni_result_invalid")?;
        if interfaces[0].get("sandbox").is_some_and(|v| v != "") || interfaces[1]["name"] != IFNAME || interfaces[1]["sandbox"] != attachment.netns
            || result["ips"].as_array().is_none_or(|ips| ips.len() != 1 || ips[0]["address"] != format!("{GUEST}/30")
                || ips[0]["gateway"] != GATEWAY || ips[0]["interface"] != 1) { return Err("cni_result_invalid"); }
        for (namespace, name) in [(self.slot_namespace(attachment.slot), host), (attachment.netns.clone().into(), IFNAME)] {
            let out = self.helpers.run(self.tool("ip")?, &["-j".into(), "link".into(), "show".into(), "dev".into(), name.into()],
                Duration::from_secs(3), LIMIT, false, &self.search_path, Some(&namespace))?;
            let links: Value = serde_json::from_str(&out.stdout).map_err(|_| "cni_mtu_invalid")?;
            if out.interrupted || out.exit_code != Some(0) || links[0]["mtu"] != mtu { return Err("cni_mtu_invalid"); }
        }
        Ok(host.into())
    }
    // Replay DEL in reverse order from persisted intent, including failed ADDs, with libcni's final
    // cached result. Keep failed entries for retry; absent guest pins still reach ptp/static DEL.
    pub fn cni_del(&self, id: &str, slot: usize) -> Result<()> {
        let path = self.private(id).join("cni.json");
        if !path.exists() { return Ok(()); }
        let mut attachment: Attachment = storage::read_json(&path, LIMIT as u64)?;
        if attachment.version != 1 || attachment.id != id || attachment.slot != slot
            || attachment.netns != format!("/run/netns/{}", self.guest_name(id)) || attachment.plugins.len() != 1
            || attachment.plugins[0].config["type"] != "ptp" || attachment.plugins[0].config["ipam"]["type"] != "static" {
            return Err("cni_cache_invalid");
        }
        let previous = attachment.plugins.iter().rev().find_map(|p| p.result.clone());
        let mut failure = None;
        for index in (0..attachment.plugins.len()).rev() {
            if !attachment.plugins[index].attempted { continue; }
            // Both routing domain and guest gone means the kernel already removed the link; static
            // has no allocation database. Never fall back to running a plugin in the pod namespace.
            let gone = !self.slot_namespace(slot).exists() && !Path::new(&attachment.netns).exists();
            match if gone { Ok(Value::Null) } else { self.cni_invoke(&attachment, &attachment.plugins[index].config, previous.as_ref(), "DEL") } {
                Ok(_) => { attachment.plugins[index].attempted = false; process::atomic_json(&path, &attachment)?; }
                Err(e) => { failure.get_or_insert(e); }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

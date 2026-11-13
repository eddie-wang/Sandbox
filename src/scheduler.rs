use std::time::{Duration, Instant};
use crate::{controller::NodeView, model::CreateSpec};

// A create the controller sent (or is about to send) to a node: its requested memory and vCPUs and,
// once its answer arrived, when that was.
struct Placement { id: u64, node: String, memory_mib: u64, vcpus: u32, ended: Option<Instant> }

// Recent creates per node that the node's last status may not count yet, plus the round-robin turn
// for equal scores. Creates sent at the same moment then spread over the nodes instead of all ranking
// one stale snapshot the same way (AgentENV round-robin intent, kept capacity-aware). A create can
// briefly count twice (in a poll and here); worker admission stays the authority. The controller
// holds this under a plain mutex only for these in-memory steps, never across I/O.
#[derive(Default)]
pub struct Placements { entries: Vec<Placement>, next_id: u64, turn: u64 }

// Most recent creates remembered at once; the oldest answered ones are dropped first.
const MAX_PLACEMENTS: usize = 4096;

impl Placements {
    // Forget answered creates that a newer status of their node already counts (its poll started after
    // the answer arrived), that were answered longer than `keep` ago, or whose node is not configured.
    fn prune(&mut self, nodes: &[NodeView], keep: Duration) {
        let now = Instant::now();
        self.entries.retain(|p| match p.ended {
            None => true,
            Some(ended) => now.duration_since(ended) < keep
                && nodes.iter().any(|n| n.node_id == p.node && !n.polled_at.is_some_and(|polled| polled > ended)),
        });
    }
    // Remember a create about to be sent to `node` (counted until it is answered and a newer poll counts
    // it) and return its ID. At the size limit the oldest answered create is forgotten first.
    pub fn start(&mut self, node: &str, request: &CreateSpec) -> u64 {
        if self.entries.len() >= MAX_PLACEMENTS {
            let oldest = self.entries.iter().enumerate().filter_map(|(i, p)| p.ended.map(|t| (t, i))).min().map(|(_, i)| i);
            if let Some(i) = oldest { self.entries.remove(i); }
        }
        self.next_id += 1;
        self.entries.push(Placement { id: self.next_id, node: node.to_owned(), memory_mib: request.memory_mib.unwrap_or(0), vcpus: request.vcpus.unwrap_or(0), ended: None });
        self.next_id
    }
    // Record that a create was answered. One that may hold capacity on its node stays counted until a
    // newer poll; one the node refused before reserving anything is forgotten at once.
    pub fn finish(&mut self, id: u64, may_hold_capacity: bool) {
        if may_hold_capacity {
            if let Some(p) = self.entries.iter_mut().find(|p| p.id == id) { p.ended.get_or_insert_with(Instant::now); }
        } else {
            self.entries.retain(|p| p.id != id);
        }
    }
    // Rank the candidates with recent creates added to each node's usage, using the next round-robin
    // turn for equal scores, and remember a create to the first candidate. Return the ranking and that
    // create's ID. Answered creates older than `keep` no longer count.
    pub fn choose<'a>(&mut self, nodes: &'a [NodeView], request: &CreateSpec, keep: Duration) -> (Vec<&'a str>, Option<u64>) {
        self.prune(nodes, keep);
        let turn = self.turn;
        self.turn = self.turn.wrapping_add(1);
        let ranked = rank(nodes, request, &self.entries, turn);
        let id = ranked.first().map(|node| self.start(node, request));
        (ranked, id)
    }
}

// Return fresh, ready Linux candidates with room, counting the recent creates in `placements` as
// used: least projected load first, then fewer active restores, then round-robin from `turn`. Advisory
// only; worker admission stays atomic. Templates are not read here: a worker without a compatible one
// rejects before launch and the controller tries the next. Omitted resources count as zero here.
fn rank<'a>(nodes: &'a [NodeView], request: &CreateSpec, placements: &[Placement], turn: u64) -> Vec<&'a str> {
    let count = nodes.len().max(1) as u64;
    let mut candidates: Vec<_> = nodes.iter().enumerate().filter_map(|(index, node)| {
        let status = node.status.as_ref()?;
        let mut usage = status.usage.clone()?;
        for p in placements.iter().filter(|p| p.node == node.node_id) {
            usage.memory_mib = usage.memory_mib.saturating_add(p.memory_mib);
            usage.vcpus = usage.vcpus.saturating_add(p.vcpus);
            usage.sandboxes = usage.sandboxes.saturating_add(1);
        }
        let capacity = &status.capacity;
        let (memory_mib, vcpus) = (request.memory_mib.unwrap_or(0), request.vcpus.unwrap_or(0));
        if !node.fresh || !status.admission_ready || status.os != "linux"
            || !status.runtimes.iter().any(|runtime| runtime.ready)
            || memory_mib > capacity.memory_mib.saturating_sub(usage.memory_mib)
            || vcpus > capacity.vcpus.saturating_mul(status.cpu_overcommit).saturating_sub(usage.vcpus)
            || usage.sandboxes >= capacity.max_sandboxes
            || usage.restores >= capacity.max_concurrent_restores
        {
            return None;
        }
        // Restore slots are transient and gate admission above; counting them in
        // the load would tie every idle node and pack all creates onto one name.
        let projected_load = [
            (usage.memory_mib + memory_mib) as f64 / capacity.memory_mib as f64,
            (usage.vcpus + vcpus) as f64 / (capacity.vcpus * status.cpu_overcommit) as f64,
            (usage.sandboxes + 1) as f64 / capacity.max_sandboxes as f64,
        ].into_iter().fold(0.0, f64::max);
        // Equal scores take turns: the configured order, rotated by one per create.
        let order = (index as u64 + count - turn % count) % count;
        Some((node.node_id.as_str(), projected_load, usage.restores, order))
    }).collect();
    candidates.sort_by(|left, right| left.1.total_cmp(&right.1).then(left.2.cmp(&right.2)).then(left.3.cmp(&right.3)));
    candidates.into_iter().map(|(node_id, _, _, _)| node_id).collect()
}

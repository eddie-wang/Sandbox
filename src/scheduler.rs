use crate::{controller::NodeView, model::CreateRequest};

// Filter only the supplied candidates for freshness, runtime readiness, compatibility and available
// budgets. Score each by its highest projected reservation fraction; choose the lowest score, breaking
// ties by node ID. This is advisory, not a reservation: the worker still admits atomically and checks
// template digests and exact compatibility.
pub fn choose<'a>(nodes: &'a [NodeView], request: &CreateRequest) -> Option<&'a str> {
    nodes.iter().filter_map(|node| {
        let status = node.status.as_ref()?;
        let usage = status.usage.as_ref()?;
        let capacity = &status.capacity;
        if !node.fresh || !status.admission_ready || status.os != "linux"
            || status.architecture != request.architecture
            || !status.runtimes.iter().any(|runtime| runtime.runtime == request.runtime && runtime.ready)
            || request.memory_mib > capacity.memory_mib.saturating_sub(usage.memory_mib)
            || request.vcpus > capacity.vcpus.saturating_mul(status.cpu_overcommit).saturating_sub(usage.vcpus)
            || usage.sandboxes >= capacity.max_sandboxes
            || usage.restores >= capacity.max_concurrent_restores
        {
            return None;
        }
        let projected_load = [
            (usage.memory_mib + request.memory_mib) as f64 / capacity.memory_mib as f64,
            (usage.vcpus + request.vcpus) as f64 / (capacity.vcpus * status.cpu_overcommit) as f64,
            (usage.sandboxes + 1) as f64 / capacity.max_sandboxes as f64,
            (usage.restores + 1) as f64 / capacity.max_concurrent_restores as f64,
        ].into_iter().fold(0.0, f64::max);
        Some((node.node_id.as_str(), projected_load))
    }).min_by(|left, right| left.1.total_cmp(&right.1).then_with(|| left.0.cmp(right.0)))
        .map(|(node_id, _)| node_id)
}

use crate::{controller::NodeView, model::CreateSpec};

// Advisory only. A snapshot is not a reservation; worker-side atomic admission remains required.
// The controller does not read templates: a worker that lacks a compatible template
// (including architecture) rejects before launch and the controller tries the next.
// Omitted resources default to the template's values and count as zero here.
// Returns fresh, ready, compatible candidates: least projected load first, then
// fewer active restores, then node ID.
pub fn rank<'a>(nodes: &'a [NodeView], request: &CreateSpec) -> Vec<&'a str> {
    let mut candidates: Vec<_> = nodes.iter().filter_map(|node| {
        let status = node.status.as_ref()?;
        let usage = status.usage.as_ref()?;
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
        Some((node.node_id.as_str(), projected_load, usage.restores))
    }).collect();
    candidates.sort_by(|left, right| left.1.total_cmp(&right.1).then(left.2.cmp(&right.2)).then_with(|| left.0.cmp(right.0)));
    candidates.into_iter().map(|(node_id, _, _)| node_id).collect()
}

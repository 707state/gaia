use super::*;

#[derive(Debug, Serialize)]
struct ProcessDetail {
    pid: u32,
    name: String,
    state: String,
    ppid: u32,
    uid: u32,
    gid: u32,
    euid: u32,
    egid: u32,
    threads: u32,
    cmdline: String,
    exe: String,
    cwd: String,
    uptime_secs: u64,
    mem: ProcessMemory,
    io: ProcessIo,
    fds: Vec<FdEntry>,
    voluntary_ctxt_switches: u64,
    nonvoluntary_ctxt_switches: u64,
    oom_score: i32,
    seccomp: String,
    cap_eff: String,
    environ: Vec<String>,
    cpus_allowed_list: String,
}

#[derive(Debug, Serialize)]
struct ProcessMemory {
    vm_peak_kb: u64,
    vm_size_kb: u64,
    vm_rss_kb: u64,
    vm_swap_kb: u64,
    vm_data_kb: u64,
    vm_stk_kb: u64,
    vm_exe_kb: u64,
    vm_lib_kb: u64,
}

#[derive(Debug, Serialize)]
struct ProcessIo {
    rchar: u64,
    wchar: u64,
    syscr: u64,
    syscw: u64,
    read_bytes: u64,
    write_bytes: u64,
}

#[derive(Debug, Serialize)]
struct FdEntry {
    fd: i32,
    target: String,
}

fn read_proc(pid: u32, file: &str) -> String {
    fs::read_to_string(format!("/proc/{pid}/{file}")).unwrap_or_default()
}

fn status_kb(status: &str, key: &str) -> u64 {
    for line in status.lines() {
        if line.starts_with(key) {
            let val = line.split_whitespace().nth(1).unwrap_or("0");
            return val.parse().unwrap_or(0);
        }
    }
    0
}

fn status_val(status: &str, key: &str) -> String {
    for line in status.lines() {
        if line.starts_with(key) {
            return line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
        }
    }
    String::new()
}

fn io_val(io: &str, key: &str) -> u64 {
    for line in io.lines() {
        if line.starts_with(key) {
            let val = line.splitn(2, ':').nth(1).unwrap_or("0").trim();
            return val.parse().unwrap_or(0);
        }
    }
    0
}

fn compute_uptime_secs(pid: u32) -> u64 {
    let stat = read_proc(pid, "stat");
    let after_comm = match stat.rfind(')') {
        Some(pos) => &stat[pos + 2..],
        None => return 0,
    };
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    if fields.len() < 20 {
        return 0;
    }
    let starttime_ticks: u64 = fields[19].parse().unwrap_or(0);
    let clk_tck: u64 = 100;

    let uptime_str = fs::read_to_string("/proc/uptime").unwrap_or_default();
    let system_uptime_secs: f64 = uptime_str
        .split_whitespace()
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0.0);

    let process_start_secs = starttime_ticks / clk_tck;
    let uptime = system_uptime_secs as u64;
    uptime.saturating_sub(process_start_secs)
}

fn read_process_detail(pid: u32) -> Option<ProcessDetail> {
    let status = read_proc(pid, "status");
    if status.is_empty() {
        return None;
    }

    let name = status_val(&status, "Name:");
    let state = status_val(&status, "State:");
    let ppid: u32 = status_val(&status, "PPid:").parse().unwrap_or(0);
    let threads: u32 = status_val(&status, "Threads:").parse().unwrap_or(0);

    let uid_line = status_val(&status, "Uid:");
    let uid_parts: Vec<u32> = uid_line.split_whitespace().filter_map(|s| s.parse().ok()).collect();
    let uid = uid_parts.first().copied().unwrap_or(0);
    let euid = uid_parts.get(1).copied().unwrap_or(0);

    let gid_line = status_val(&status, "Gid:");
    let gid_parts: Vec<u32> = gid_line.split_whitespace().filter_map(|s| s.parse().ok()).collect();
    let gid = gid_parts.first().copied().unwrap_or(0);
    let egid = gid_parts.get(1).copied().unwrap_or(0);

    let cmdline_raw = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let cmdline = cmdline_raw
        .split(|b| *b == 0)
        .map(|s| String::from_utf8_lossy(s).to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let cwd = fs::read_link(format!("/proc/{pid}/cwd"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let mem = ProcessMemory {
        vm_peak_kb: status_kb(&status, "VmPeak:"),
        vm_size_kb: status_kb(&status, "VmSize:"),
        vm_rss_kb: status_kb(&status, "VmRSS:"),
        vm_swap_kb: status_kb(&status, "VmSwap:"),
        vm_data_kb: status_kb(&status, "VmData:"),
        vm_stk_kb: status_kb(&status, "VmStk:"),
        vm_exe_kb: status_kb(&status, "VmExe:"),
        vm_lib_kb: status_kb(&status, "VmLib:"),
    };

    let io_raw = read_proc(pid, "io");
    let io = ProcessIo {
        rchar: io_val(&io_raw, "rchar:"),
        wchar: io_val(&io_raw, "wchar:"),
        syscr: io_val(&io_raw, "syscr:"),
        syscw: io_val(&io_raw, "syscw:"),
        read_bytes: io_val(&io_raw, "read_bytes:"),
        write_bytes: io_val(&io_raw, "write_bytes:"),
    };

    let mut fds = Vec::new();
    if let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) {
        for entry in entries.flatten() {
            if let Ok(fd_num) = entry.file_name().to_string_lossy().parse::<i32>() {
                let target = fs::read_link(entry.path())
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "?".into());
                fds.push(FdEntry { fd: fd_num, target });
            }
        }
    }
    fds.sort_by_key(|f| f.fd);

    let voluntary_ctxt_switches: u64 = status_val(&status, "voluntary_ctxt_switches:")
        .parse()
        .unwrap_or(0);
    let nonvoluntary_ctxt_switches: u64 = status_val(&status, "nonvoluntary_ctxt_switches:")
        .parse()
        .unwrap_or(0);

    let oom_score: i32 = read_proc(pid, "oom_score").trim().parse().unwrap_or(0);
    let seccomp = status_val(&status, "Seccomp:");
    let cap_eff = status_val(&status, "CapEff:");
    let cpus_allowed_list = status_val(&status, "Cpus_allowed_list:");

    let environ_raw = fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
    let environ: Vec<String> = environ_raw
        .split(|b| *b == 0)
        .map(|s| String::from_utf8_lossy(s).to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let uptime_secs = compute_uptime_secs(pid);

    Some(ProcessDetail {
        pid,
        name,
        state,
        ppid,
        uid,
        gid,
        euid,
        egid,
        threads,
        cmdline,
        exe,
        cwd,
        uptime_secs,
        mem,
        io,
        fds,
        voluntary_ctxt_switches,
        nonvoluntary_ctxt_switches,
        oom_score,
        seccomp,
        cap_eff,
        environ,
        cpus_allowed_list,
    })
}

pub(crate) async fn api_process_detail(AxumPath(pid): AxumPath<u32>) -> Response {
    match read_process_detail(pid) {
        Some(detail) => Json(detail).into_response(),
        None => (StatusCode::NOT_FOUND, format!("process {pid} not found")).into_response(),
    }
}

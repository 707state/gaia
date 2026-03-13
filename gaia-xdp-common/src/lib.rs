#![no_std]

pub const DETAIL_LEN: usize = 128;
pub const COMM_LEN: usize = 16;
pub const ADDR_LEN: usize = 16;

pub const EVENT_KIND_FILE_IO: u8 = 1;
pub const EVENT_KIND_PROCESS: u8 = 2;
pub const EVENT_KIND_PRIVILEGE: u8 = 3;
pub const EVENT_KIND_NETWORK: u8 = 4;
pub const EVENT_KIND_HOTPATCH: u8 = 5;

pub const EVENT_ACTION_ENTER: u8 = 1;
pub const EVENT_ACTION_EXIT: u8 = 2;
pub const EVENT_ACTION_ALERT: u8 = 3;
pub const EVENT_ACTION_BLOCKED: u8 = 4;

pub const PROTOCOL_UNKNOWN: u8 = 0;
pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub kind: u8,
    pub action: u8,
    pub protocol: u8,
    pub reserved: u8,
    pub port: u16,
    pub reserved2: u16,
    pub addr: [u8; ADDR_LEN],
    pub comm: [u8; COMM_LEN],
    pub detail: [u8; DETAIL_LEN],
}

impl KernelEvent {
    pub const fn empty() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            tgid: 0,
            uid: 0,
            gid: 0,
            kind: 0,
            action: 0,
            protocol: 0,
            reserved: 0,
            port: 0,
            reserved2: 0,
            addr: [0; ADDR_LEN],
            comm: [0; COMM_LEN],
            detail: [0; DETAIL_LEN],
        }
    }
}

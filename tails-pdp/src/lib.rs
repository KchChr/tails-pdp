pub mod policy_loader;
pub mod time;

pub const TAIL_IDX_POLICY_1: u32 = 0;
pub const TAIL_IDX_POLICY_2: u32 = 1;
pub const COMBINE: u32 = 2;
pub const BPF_PIN_DIRECTORY: &str = "/sys/fs/bpf/tails-pdp";

pub struct LsmProgramSpec {
    pub name: &'static str,
    pub hook: &'static str,
    pub attach: bool,
}

pub const LSM_PROGRAMS: [LsmProgramSpec; 5] = [
    LsmProgramSpec {
        name: "file_open",
        hook: "file_open",
        attach: true,
    },
    LsmProgramSpec {
        name: "task_setnice",
        hook: "task_setnice",
        attach: true,
    },
    LsmProgramSpec {
        name: "evaluate_static_policies",
        hook: "file_open",
        attach: false,
    },
    LsmProgramSpec {
        name: "evaluate_stream_policies",
        hook: "file_open",
        attach: false,
    },
    LsmProgramSpec {
        name: "combine",
        hook: "file_open",
        attach: false,
    },
];

pub const TAIL_PROGRAMS: [(u32, &str); 3] = [
    (TAIL_IDX_POLICY_1, "evaluate_static_policies"),
    (TAIL_IDX_POLICY_2, "evaluate_stream_policies"),
    (COMBINE, "combine"),
];

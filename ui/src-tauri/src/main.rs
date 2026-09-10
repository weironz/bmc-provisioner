//! The desktop shell owns only the local API process it started itself.
//!
//! The UI is a normal Tauri webview and talks to `bmc-provisionerd` on loopback. Keeping the
//! Redfish workflow in the service prevents desktop and future container deployments from
//! drifting apart.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

use tauri::{Manager, RunEvent};

const SERVICE_ADDRESS: &str = "127.0.0.1:6770";

/// Only a child spawned by this process is stored and terminated on exit. A manually started
/// service belongs to the operator and is deliberately left alone.
struct LocalService(Mutex<Option<Child>>);

fn service_is_up() -> bool {
    let addresses: Vec<SocketAddr> = match SERVICE_ADDRESS.to_socket_addrs() {
        Ok(addresses) => addresses.collect(),
        Err(_) => return false,
    };
    addresses
        .iter()
        .any(|address| TcpStream::connect_timeout(address, Duration::from_millis(350)).is_ok())
}

/// Locate the Tauri-packaged sidecar, falling back to the repository service build for development.
fn sidecar_path() -> Option<PathBuf> {
    let filename = if cfg!(windows) {
        "bmc-provisionerd.exe"
    } else {
        "bmc-provisionerd"
    };
    let executable_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let mut paths = vec![executable_dir.join(filename)];
    for relative in ["../../../../target/release", "../../../../target/debug"] {
        paths.push(executable_dir.join(relative).join(filename));
    }
    paths.into_iter().find(|path| path.exists())
}

#[cfg(windows)]
mod child_lifecycle {
    use std::sync::OnceLock;

    use windows_sys::Win32::{
        Foundation::HANDLE,
        System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        },
    };

    struct Job(HANDLE);
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    static JOB: OnceLock<Option<Job>> = OnceLock::new();

    fn job() -> Option<HANDLE> {
        JOB.get_or_init(|| unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return None;
            }
            let mut configuration: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            configuration.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &configuration as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                None
            } else {
                Some(Job(handle))
            }
        })
        .as_ref()
        .map(|job| job.0)
    }

    pub fn adopt(child: &std::process::Child) {
        use std::os::windows::io::AsRawHandle;

        if let Some(job) = job() {
            unsafe {
                AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE);
            }
        }
    }
}

#[cfg(not(windows))]
mod child_lifecycle {
    pub fn adopt(_child: &std::process::Child) {}
}

fn spawn_service(state: &LocalService) -> Result<(), String> {
    let sidecar = sidecar_path().ok_or("找不到 bmc-provisionerd，桌面程序可能安装不完整")?;
    let mut command = Command::new(sidecar);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("启动本地服务失败：{error}"))?;
    child_lifecycle::adopt(&child);

    let deadline = Instant::now() + Duration::from_secs(6);
    while !service_is_up() {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("本地服务启动后立即退出：{status}"));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err("等待本地服务就绪超时".to_owned());
        }
        std::thread::sleep(Duration::from_millis(120));
    }
    *state
        .0
        .lock()
        .map_err(|_| "本地服务状态锁异常".to_owned())? = Some(child);
    Ok(())
}

/// 安装更新前仅停止桌面壳自己拉起的 sidecar。
///
/// 若 6770 端口是操作者独立启动的服务，占用它的进程不属于桌面端，不能为了
/// 更新外壳而杀掉它。此时安装仍可继续，只是新 sidecar 会在下次重启该服务后生效。
#[tauri::command]
fn stop_local_service(state: tauri::State<'_, LocalService>) -> Result<bool, String> {
    let mut child = state
        .0
        .lock()
        .map_err(|_| "本地服务状态锁异常".to_owned())?;
    let Some(process) = child.as_mut() else {
        return Ok(false);
    };
    process
        .kill()
        .map_err(|error| format!("无法停止本机服务：{error}"))?;
    let _ = process.wait();
    *child = None;
    Ok(true)
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .invoke_handler(tauri::generate_handler![stop_local_service])
        .manage(LocalService(Mutex::new(None)))
        .setup(|app| {
            if !service_is_up() {
                let state = app.state::<LocalService>();
                spawn_service(&state)
                    .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("desktop shell failed to start")
        .run(|app, event| {
            if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit)
                && let Some(state) = app.try_state::<LocalService>()
                && let Ok(mut child) = state.0.lock()
            {
                if let Some(process) = child.as_mut() {
                    let _ = process.kill();
                    let _ = process.wait();
                }
                *child = None;
            }
        });
}

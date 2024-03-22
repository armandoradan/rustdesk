use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        #[cfg(feature = "appimage")]
        let prefix = std::env::var("APPDIR").unwrap_or("".to_string());
        #[cfg(not(feature = "appimage"))]
        let prefix = "".to_string();
        #[cfg(feature = "flatpak")]
        let dir = "/app";
        #[cfg(not(feature = "flatpak"))]
        let dir = "/usr";
        sciter::set_library(&(prefix + dir + "/lib/rustdesk/libsciter-gtk.so")).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String) -> String {
        test_if_valid_server(host)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_gpucodec(&self) -> bool {
        has_gpucodec()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_gpucodec();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
         "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAZAAAAG1CAYAAADX3qJJAAAACXBIWXMAAAsTAAALEwEAmpwYAAAKfmlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDUgNzkuMTYzNDk5LCAyMDE4LzA4LzEzLTE2OjQwOjIyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6cGhvdG9zaG9wPSJodHRwOi8vbnMuYWRvYmUuY29tL3Bob3Rvc2hvcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ0MgMjAxOSAoV2luZG93cykiIHhtcDpDcmVhdGVEYXRlPSIyMDIwLTEyLTE3VDEyOjA1OjAxKzAzOjMwIiB4bXA6TW9kaWZ5RGF0ZT0iMjAyMi0xMi0yNFQxNTo0MTo1MSswMzozMCIgeG1wOk1ldGFkYXRhRGF0ZT0iMjAyMi0xMi0yNFQxNTo0MTo1MSswMzozMCIgZGM6Zm9ybWF0PSJpbWFnZS9wbmciIHBob3Rvc2hvcDpDb2xvck1vZGU9IjMiIHBob3Rvc2hvcDpJQ0NQcm9maWxlPSJzUkdCIElFQzYxOTY2LTIuMSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDphYTI2ZjM4OC00YmU4LTA4NDktYjQ4NS1lMTFiNmNlMGIzYzUiIHhtcE1NOkRvY3VtZW50SUQ9ImFkb2JlOmRvY2lkOnBob3Rvc2hvcDplZGQwMmQ0Yy1hZmMzLWNiNDItODRmOS1hZGIwMDUzZTJmZmMiIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDo0MmM2NzJkZS0yNTA0LTE0NGQtYWRiMS00ZTUxNDg3OTY1ZDIiPiA8cGhvdG9zaG9wOkRvY3VtZW50QW5jZXN0b3JzPiA8cmRmOkJhZz4gPHJkZjpsaT4xRTk0RDc4ODE2QjdGRDQ4NDJBMzdGNjgwNkEzQTgyNzwvcmRmOmxpPiA8cmRmOmxpPjJCQjQ4QjQ3MEY3NzVGMDYzRjVFOTBFNzczMUMzNUJBPC9yZGY6bGk+IDxyZGY6bGk+NEM0M0EwNjlENDdEMzc1OUEyRjYwOEM0REJGQjYwRkE8L3JkZjpsaT4gPHJkZjpsaT41MjM5RUMzNTFBN0Y2NUU2MjhDNEJGN0IyRTlEMzE0NDwvcmRmOmxpPiA8cmRmOmxpPjhCM0Q3N0I2MkYyMUJDQTk5NTRCMTg1MkM4RTI3NTM5PC9yZGY6bGk+IDxyZGY6bGk+OTVEQ0RENDJBQjYwRDE0QzE4REZBMjhDQjA5OEI3RTE8L3JkZjpsaT4gPHJkZjpsaT45REQ0ODlGOTE1M0I2MjMzNzlDMjMyREQ2NTQzNDMxMDwvcmRmOmxpPiA8cmRmOmxpPkE0MTJGMDc0MDI0QjgwODQ5QjgyMTEzNzgwMDFGNzRDPC9yZGY6bGk+IDxyZGY6bGk+QjEzMDMzQzMyRDEwMDRFQUVDNkMxMUIzQ0RBMzcxMjI8L3JkZjpsaT4gPHJkZjpsaT5CN0I3MDAxRTJEM0FGMzFFMDlFNDc2NTU0RkZCQUFBNTwvcmRmOmxpPiA8cmRmOmxpPkRGMjA1MTYzMDYwNkRENUQxRTAyRUMxMjVBQkNENTY5PC9yZGY6bGk+IDxyZGY6bGk+YWRvYmU6ZG9jaWQ6cGhvdG9zaG9wOjA3MzUyYzJhLWQ2MzQtN2M0OS05YjlhLTk1ZDUxYTIwZDU4MDwvcmRmOmxpPiA8cmRmOmxpPnhtcC5kaWQ6MzcyYTFjNjctYTA5NS01NDRiLWJlMDEtMTdkYWY0ZDFjNWRlPC9yZGY6bGk+IDxyZGY6bGk+eG1wLmRpZDozOTYwOEUxMDU5MEUxMUVEQUE0QkI0MEE4QUQ3QTU1NDwvcmRmOmxpPiA8cmRmOmxpPnhtcC5kaWQ6NUVCNDdFNjU4NjQ4RTIxMThDMEI4NDBFQzgxOTdGNjA8L3JkZjpsaT4gPHJkZjpsaT54bXAuZGlkOmM1ODQ5YTJiLTEwMDktMmU0My1hMTZkLTQxYTc1ZWMwNmUzMjwvcmRmOmxpPiA8L3JkZjpCYWc+IDwvcGhvdG9zaG9wOkRvY3VtZW50QW5jZXN0b3JzPiA8eG1wTU06SGlzdG9yeT4gPHJkZjpTZXE+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJjcmVhdGVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjQyYzY3MmRlLTI1MDQtMTQ0ZC1hZGIxLTRlNTE0ODc5NjVkMiIgc3RFdnQ6d2hlbj0iMjAyMC0xMi0xN1QxMjowNTowMSswMzozMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTkgKFdpbmRvd3MpIi8+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJzYXZlZCIgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDoxNDg0MTk5Ny04ZGE2LTM3NGYtOTlkZC0yMjAzYjhjMGUwNjMiIHN0RXZ0OndoZW49IjIwMjAtMTItMTdUMTI6MDc6MjUrMDM6MzAiIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkFkb2JlIFBob3Rvc2hvcCBDQyAyMDE5IChXaW5kb3dzKSIgc3RFdnQ6Y2hhbmdlZD0iLyIvPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6YWEyNmYzODgtNGJlOC0wODQ5LWI0ODUtZTExYjZjZTBiM2M1IiBzdEV2dDp3aGVuPSIyMDIyLTEyLTI0VDE1OjQxOjUxKzAzOjMwIiBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZG9iZSBQaG90b3Nob3AgQ0MgMjAxOSAoV2luZG93cykiIHN0RXZ0OmNoYW5nZWQ9Ii8iLz4gPC9yZGY6U2VxPiA8L3htcE1NOkhpc3Rvcnk+IDwvcmRmOkRlc2NyaXB0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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAZAAAAG1CAYAAADX3qJJAAAACXBIWXMAAAsTAAALEwEAmpwYAAAKfmlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDUgNzkuMTYzNDk5LCAyMDE4LzA4LzEzLTE2OjQwOjIyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6cGhvdG9zaG9wPSJodHRwOi8vbnMuYWRvYmUuY29tL3Bob3Rvc2hvcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ0MgMjAxOSAoV2luZG93cykiIHhtcDpDcmVhdGVEYXRlPSIyMDIwLTEyLTE3VDEyOjA1OjAxKzAzOjMwIiB4bXA6TW9kaWZ5RGF0ZT0iMjAyMi0xMi0yNFQxNTo0MTo1MSswMzozMCIgeG1wOk1ldGFkYXRhRGF0ZT0iMjAyMi0xMi0yNFQxNTo0MTo1MSswMzozMCIgZGM6Zm9ybWF0PSJpbWFnZS9wbmciIHBob3Rvc2hvcDpDb2xvck1vZGU9IjMiIHBob3Rvc2hvcDpJQ0NQcm9maWxlPSJzUkdCIElFQzYxOTY2LTIuMSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDphYTI2ZjM4OC00YmU4LTA4NDktYjQ4NS1lMTFiNmNlMGIzYzUiIHhtcE1NOkRvY3VtZW50SUQ9ImFkb2JlOmRvY2lkOnBob3Rvc2hvcDplZGQwMmQ0Yy1hZmMzLWNiNDItODRmOS1hZGIwMDUzZTJmZmMiIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDo0MmM2NzJkZS0yNTA0LTE0NGQtYWRiMS00ZTUxNDg3OTY1ZDIiPiA8cGhvdG9zaG9wOkRvY3VtZW50QW5jZXN0b3JzPiA8cmRmOkJhZz4gPHJkZjpsaT4xRTk0RDc4ODE2QjdGRDQ4NDJBMzdGNjgwNkEzQTgyNzwvcmRmOmxpPiA8cmRmOmxpPjJCQjQ4QjQ3MEY3NzVGMDYzRjVFOTBFNzczMUMzNUJBPC9yZGY6bGk+IDxyZGY6bGk+NEM0M0EwNjlENDdEMzc1OUEyRjYwOEM0REJGQjYwRkE8L3JkZjpsaT4gPHJkZjpsaT41MjM5RUMzNTFBN0Y2NUU2MjhDNEJGN0IyRTlEMzE0NDwvcmRmOmxpPiA8cmRmOmxpPjhCM0Q3N0I2MkYyMUJDQTk5NTRCMTg1MkM4RTI3NTM5PC9yZGY6bGk+IDxyZGY6bGk+OTVEQ0RENDJBQjYwRDE0QzE4REZBMjhDQjA5OEI3RTE8L3JkZjpsaT4gPHJkZjpsaT45REQ0ODlGOTE1M0I2MjMzNzlDMjMyREQ2NTQzNDMxMDwvcmRmOmxpPiA8cmRmOmxpPkE0MTJGMDc0MDI0QjgwODQ5QjgyMTEzNzgwMDFGNzRDPC9yZGY6bGk+IDxyZGY6bGk+QjEzMDMzQzMyRDEwMDRFQUVDNkMxMUIzQ0RBMzcxMjI8L3JkZjpsaT4gPHJkZjpsaT5CN0I3MDAxRTJEM0FGMzFFMDlFNDc2NTU0RkZCQUFBNTwvcmRmOmxpPiA8cmRmOmxpPkRGMjA1MTYzMDYwNkRENUQxRTAyRUMxMjVBQkNENTY5PC9yZGY6bGk+IDxyZGY6bGk+YWRvYmU6ZG9jaWQ6cGhvdG9zaG9wOjA3MzUyYzJhLWQ2MzQtN2M0OS05YjlhLTk1ZDUxYTIwZDU4MDwvcmRmOmxpPiA8cmRmOmxpPnhtcC5kaWQ6MzcyYTFjNjctYTA5NS01NDRiLWJlMDEtMTdkYWY0ZDFjNWRlPC9yZGY6bGk+IDxyZGY6bGk+eG1wLmRpZDozOTYwOEUxMDU5MEUxMUVEQUE0QkI0MEE4QUQ3QTU1NDwvcmRmOmxpPiA8cmRmOmxpPnhtcC5kaWQ6NUVCNDdFNjU4NjQ4RTIxMThDMEI4NDBFQzgxOTdGNjA8L3JkZjpsaT4gPHJkZjpsaT54bXAuZGlkOmM1ODQ5YTJiLTEwMDktMmU0My1hMTZkLTQxYTc1ZWMwNmUzMjwvcmRmOmxpPiA8L3JkZjpCYWc+IDwvcGhvdG9zaG9wOkRvY3VtZW50QW5jZXN0b3JzPiA8eG1wTU06SGlzdG9yeT4gPHJkZjpTZXE+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJjcmVhdGVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjQyYzY3MmRlLTI1MDQtMTQ0ZC1hZGIxLTRlNTE0ODc5NjVkMiIgc3RFdnQ6d2hlbj0iMjAyMC0xMi0xN1QxMjowNTowMSswMzozMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTkgKFdpbmRvd3MpIi8+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJzYXZlZCIgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDoxNDg0MTk5Ny04ZGE2LTM3NGYtOTlkZC0yMjAzYjhjMGUwNjMiIHN0RXZ0OndoZW49IjIwMjAtMTItMTdUMTI6MDc6MjUrMDM6MzAiIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkFkb2JlIFBob3Rvc2hvcCBDQyAyMDE5IChXaW5kb3dzKSIgc3RFdnQ6Y2hhbmdlZD0iLyIvPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6YWEyNmYzODgtNGJlOC0wODQ5LWI0ODUtZTExYjZjZTBiM2M1IiBzdEV2dDp3aGVuPSIyMDIyLTEyLTI0VDE1OjQxOjUxKzAzOjMwIiBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZG9iZSBQaG90b3Nob3AgQ0MgMjAxOSAoV2luZG93cykiIHN0RXZ0OmNoYW5nZWQ9Ii8iLz4gPC9yZGY6U2VxPiA8L3htcE1NOkhpc3Rvcnk+IDwvcmRmOkRlc2NyaXB0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".into()
    }
}

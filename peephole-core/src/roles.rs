//! The role names of this desktop's own processes, so nobody types the strings twice. The
//! shipped table (`dist/desktop-callers.toml`) names every one of them; the desktop gate checks
//! that each role string used in code exists in the table it ships.

use crate::ids::RoleName;

/// The shell (`sill`): draws the desktop and asks the person on behalf of other programs.
pub const SHELL: RoleName = RoleName::from_static("shell");
/// The desktop's portal backend (`transom`): asks the shell, is handed an input socket, captures the screen.
pub const PORTAL: RoleName = RoleName::from_static("portal");
/// The portal frontend (`xdg-desktop-portal`): the only caller of the portal backend.
pub const PORTAL_FRONTEND: RoleName = RoleName::from_static("portal_frontend");
/// The compositor (`casement`).
pub const COMPOSITOR: RoleName = RoleName::from_static("compositor");
/// The agent tier (`cuad`): the process that drives other programs for an assistant.
pub const AGENT_TIER: RoleName = RoleName::from_static("agent_tier");
/// The Settings app (`detent`).
pub const SETTINGS: RoleName = RoleName::from_static("settings");
/// The software-update service (`slipway.service`).
pub const UPDATER: RoleName = RoleName::from_static("updater");
/// The `slipway` command line: a program, not a service.
pub const UPDATER_CLI: RoleName = RoleName::from_static("updater_cli");
/// The touchpad daemon (`palmrest`).
pub const PAD_DAEMON: RoleName = RoleName::from_static("pad_daemon");
/// The keymap daemon (`keycap`).
pub const KEYMAP_DAEMON: RoleName = RoleName::from_static("keymap_daemon");
/// The accounts service (`accountd`).
pub const ACCOUNTS: RoleName = RoleName::from_static("accounts");
/// The model-access service (`inferd`).
pub const INFERENCE: RoleName = RoleName::from_static("inference");
/// The sync service (`syncd`).
pub const SYNC: RoleName = RoleName::from_static("sync");
/// The intent router (`intentd`).
pub const ROUTER: RoleName = RoleName::from_static("router");
/// The assistant companion (`companiond`).
pub const COMPANION: RoleName = RoleName::from_static("companion");
/// The memory service (`memoryd`).
pub const MEMORY: RoleName = RoleName::from_static("memory");
/// A sandbox launcher (`flatpak`): may create security contexts.
pub const SANDBOX_LAUNCHER: RoleName = RoleName::from_static("sandbox_launcher");
/// The unit manager (`systemd --user`): whose answers about units are believed.
pub const MANAGER: RoleName = RoleName::from_static("manager");

/// Every role above, for a gate that checks the shipped table against the code.
pub const ALL: [RoleName; 18] = [
    SHELL,
    PORTAL,
    PORTAL_FRONTEND,
    COMPOSITOR,
    AGENT_TIER,
    SETTINGS,
    UPDATER,
    UPDATER_CLI,
    PAD_DAEMON,
    KEYMAP_DAEMON,
    ACCOUNTS,
    INFERENCE,
    SYNC,
    ROUTER,
    COMPANION,
    MEMORY,
    SANDBOX_LAUNCHER,
    MANAGER,
];

use std::{default::Default, env, fs::read_to_string, str::FromStr};

use enquote::unquote;
use getopts::Options;

use super::error::Error;

const RUNFILE: &str = "/run/greetd.run";
const GENERAL_SERVICE: &str = "greetd";
const GREETER_SERVICE: &str = "greetd-greeter";

#[derive(Debug, Eq, PartialEq, Default)]
pub enum VtSelection {
    Next,
    Current,
    #[default]
    None,
    Specific(usize),
}

impl FromStr for VtSelection {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" | "\"none\"" => Ok(VtSelection::None),
            "current" | "\"current\"" => Ok(VtSelection::Current),
            "next" | "\"next\"" => Ok(VtSelection::Next),
            v => v
                .parse()
                .map(VtSelection::Specific)
                .map_err(|e| format!("could not parse vt number: {}", e)),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Default)]
pub struct ConfigSession {
    pub command: String,
    pub user: String,
    pub service: String,
}

#[derive(Debug, Eq, PartialEq, Default)]
pub struct ConfigInternal {
    pub session_worker: usize,
    pub worker_parent: u32,
}

#[derive(Debug, Eq, PartialEq, Default)]
pub struct ConfigTerminal {
    pub vt: VtSelection,
    pub switch: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConfigGeneral {
    pub multiseat: Option<crate::managed::Settings>,
    pub source_profile: bool,
    pub runfile: String,
    pub service: String,
}

impl Default for ConfigGeneral {
    fn default() -> Self {
        ConfigGeneral {
            multiseat: None,
            source_profile: true,
            runfile: RUNFILE.to_string(),
            service: GENERAL_SERVICE.to_string(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Default)]
pub struct ConfigFile {
    pub terminal: ConfigTerminal,
    pub general: ConfigGeneral,
    pub default_session: ConfigSession,
    pub initial_session: Option<ConfigSession>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Config {
    pub file: ConfigFile,
    pub internal: ConfigInternal,
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    println!("{}", opts.usage(&brief));
    println!("For more details, see greetd(1).");
}

fn maybe_unquote(s: &str) -> Result<String, Error> {
    Ok(match s.chars().next() {
        Some('"') | Some('\'') => unquote(s).map_err(|e| Error::ConfigError(format!("{}", e)))?,
        _ => s.to_string(),
    })
}

fn parse_config(config_str: &str) -> Result<ConfigFile, Error> {
    let config = inish::parse(config_str)?;
    let mut general = match config.get("general") {
        Some(section) => {
            let runfilestr = section.get("runfile").unwrap_or(&RUNFILE);
            let runfile = maybe_unquote(runfilestr)
                .map_err(|e| format!("unable to read general.runfile: {}", e))?;

            let servicestr = section.get("service").unwrap_or(&GENERAL_SERVICE);
            let service = maybe_unquote(servicestr)
                .map_err(|e| format!("unable to read general.service: {}", e))?;

            ConfigGeneral {
                multiseat: None,
                source_profile: section
                    .get("source_profile")
                    .unwrap_or(&"true")
                    .parse()
                    .map_err(|e| format!("could not parse source_profile: {}", e))?,
                runfile,
                service,
            }
        }

        None => Default::default(),
    };

    let default_session = match config.get("default_session") {
        Some(section) => {
            let commandstr = section
                .get("command")
                .ok_or("default_session contains no command")?;
            let command = maybe_unquote(commandstr)
                .map_err(|e| format!("unable to read default_session.command: {}", e))?;

            let userstr = section.get("user").unwrap_or(&"greeter");
            let user = maybe_unquote(userstr)
                .map_err(|e| format!("unable to read default_session.user: {}", e))?;

            let servicestr = section.get("service").unwrap_or(&GREETER_SERVICE);
            let service = maybe_unquote(servicestr)
                .map_err(|e| format!("unable to read default_session.service: {}", e))?;

            Ok(ConfigSession {
                command,
                user,
                service,
            })
        }
        None => Err("no default_session specified"),
    }?;

    let initial_session = match config.get("initial_session") {
        Some(section) => {
            let commandstr = section
                .get("command")
                .ok_or("initial_session contains no command")?;
            let command = maybe_unquote(commandstr)
                .map_err(|e| format!("unable to read initial_session.command: {}", e))?;

            let userstr = section
                .get("user")
                .ok_or("initial_session contains no user")?;
            let user = maybe_unquote(userstr)
                .map_err(|e| format!("unable to read initial_session.user: {}", e))?;

            let generalservicestr = general.service.as_str();
            let servicestr = section.get("service").unwrap_or(&generalservicestr);
            let service = maybe_unquote(servicestr)
                .map_err(|e| format!("unable to read initial_session.service: {}", e))?;

            Some(ConfigSession {
                command,
                user,
                service,
            })
        }
        None => None,
    };

    if let Some(section) = config.get("multiseat") {
        for key in section.keys() {
            if !matches!(
                *key,
                "seat"
                    | "vt"
                    | "launcher"
                    | "trusted_entrypoints"
                    | "run_directory"
                    | "test_pam_dir"
                    | "test_preload"
                    | "test_library_path"
            ) {
                return Err(format!("unknown multiseat setting: {}", key).into());
            }
        }
        let seat = maybe_unquote(section.get("seat").ok_or("multiseat.seat is required")?)?;
        let launcher = maybe_unquote(
            section
                .get("launcher")
                .unwrap_or(&"/usr/libexec/multiseatd/seat-launch"),
        )?;
        let directory = match section.get("run_directory") {
            Some(value) => maybe_unquote(value)?,
            None => format!("/run/greetd-{}", seat),
        };
        let setting = crate::managed::Settings {
            seat,
            vt: section
                .get("vt")
                .map(|value| maybe_unquote(value))
                .transpose()?
                .unwrap_or_else(|| "0".into())
                .parse::<u32>()
                .map_err(|error| error.to_string())?,
            launcher,
            entrypoints: match section.get("trusted_entrypoints") {
                Some(value) => shlex::split(&maybe_unquote(value)?)
                    .ok_or("invalid trusted_entrypoints quoting")?,
                None => Vec::new(),
            },
            directory,
            system_bus: env::var("DBUS_SYSTEM_BUS_ADDRESS").ok(),
            test_pam_dir: section
                .get("test_pam_dir")
                .map(|value| maybe_unquote(value))
                .transpose()?,
            test_preload: section
                .get("test_preload")
                .map(|value| maybe_unquote(value))
                .transpose()?,
            test_library_path: section
                .get("test_library_path")
                .map(|value| maybe_unquote(value))
                .transpose()?,
        };
        setting.validate()?;
        if config
            .get("general")
            .and_then(|section| section.get("source_profile"))
            .is_some()
            && general.source_profile
        {
            return Err("source_profile is forbidden before the trusted managed launcher".into());
        }
        general.source_profile = false;
        general.runfile = format!("{}/started-{}", setting.directory, setting.instance());
        general.multiseat = Some(setting);
    }

    let terminal = match config.get("terminal") {
        Some(section) => Ok(ConfigTerminal {
            vt: maybe_unquote(section.get("vt").ok_or("VT not specified")?)
                .map_err(|e| format!("unable to read terminal.vt: {}", e))?
                .as_str()
                .parse()?,
            switch: section
                .get("switch")
                .unwrap_or(&"true")
                .parse()
                .map_err(|e| format!("could not parse switch: {}", e))?,
        }),
        None if general.multiseat.is_some() => Ok(ConfigTerminal {
            vt: VtSelection::None,
            switch: false,
        }),
        None => Err("no terminal specified"),
    }?;

    if general.multiseat.is_some() && (terminal.vt != VtSelection::None || terminal.switch) {
        return Err("multiseatd owns the VT; terminal management must be disabled".into());
    }
    Ok(ConfigFile {
        initial_session,
        default_session,
        general,
        terminal,
    })
}

pub fn read_config() -> Result<Config, Error> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optopt("s", "socket-path", "socket path to use", "SOCKET_PATH");
    opts.optopt("c", "config", "config file to use", "CONFIG_FILE");
    opts.optopt(
        "",
        "vt",
        "immutable managed binding, or unmanaged terminal",
        "VT",
    );
    opts.optopt("", "seat", "explicit managed seat", "SEAT");
    opts.optopt(
        "",
        "worker-parent",
        "session worker parent (internal)",
        "PID",
    );
    opts.optopt(
        "w",
        "session-worker",
        "start a session worker (internal)",
        "FD",
    );
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => return Err(format!("could not parse arguments: {}", f).into()),
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        std::process::exit(0);
    }

    let internal = ConfigInternal {
        worker_parent: matches
            .opt_get::<u32>("worker-parent")
            .map_err(|error| error.to_string())?
            .unwrap_or(0),
        session_worker: matches
            .opt_get("session-worker")
            .expect("unable to parse session-worker")
            .unwrap_or(0),
    };

    if internal.session_worker > 0 {
        return Ok(Config {
            file: Default::default(),
            internal,
        });
    }

    let config_str = match matches.opt_str("config") {
        Some(v) => read_to_string(v),
        None => read_to_string("/etc/greetd/greetd.conf")
            .or_else(|_| read_to_string("/etc/greetd/config.toml")),
    }?;
    let mut file = parse_config(&config_str)?;

    if let Some(settings) = &mut file.general.multiseat {
        if let Some(seat) = matches.opt_str("seat") {
            settings.seat = seat;
        }
        if let Some(vt) = matches.opt_str("vt") {
            settings.vt = vt.parse::<u32>().map_err(|error| error.to_string())?;
        }
        settings.validate()?;
        file.general.runfile = format!("{}/started-{}", settings.directory, settings.instance());
    } else {
        if matches.opt_present("seat") {
            return Err("--seat requires explicit managed configuration".into());
        }
        if let Some(vt) = matches.opt_str("vt") {
            file.terminal.vt = vt.parse()?;
        }
    }

    if file.default_session.command.is_empty() {
        return Err(Error::ConfigError(
            "no default session user specified".to_string(),
        ));
    }
    if file.default_session.user.is_empty() {
        return Err(Error::ConfigError(
            "no default session user specified".to_string(),
        ));
    }
    if let Some(s) = &file.initial_session {
        if s.user.is_empty() {
            return Err(Error::ConfigError(
                "initial session enabled but contained no user".to_string(),
            ));
        }
        if s.command.is_empty() {
            return Err(Error::ConfigError(
                "initial session enabled but contained no command".to_string(),
            ));
        }
    }

    Ok(Config { file, internal })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config() {
        let config = parse_config(
            "
[terminal]
vt = 1
[default_session]
command = \"agreety\"
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Specific(1),
                    switch: true,
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                    service: "greetd-greeter".to_string(),
                },
                general: Default::default(),
                initial_session: None,
            }
        );
    }

    #[test]
    fn initial_session() {
        let config = parse_config(
            "
[terminal]\nvt = 1\n[default_session]\ncommand = \"agreety\"
[initial_session]
command = \"sway\"
user = \"john\"
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Specific(1),
                    switch: true,
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                    service: "greetd-greeter".to_string(),
                },
                general: Default::default(),
                initial_session: Some(ConfigSession {
                    command: "sway".to_string(),
                    user: "john".to_string(),
                    service: "greetd".to_string(),
                }),
            }
        );
    }

    #[test]
    fn general() {
        let config = parse_config(
            "
[terminal]\nvt = 1\n[default_session]\ncommand = \"agreety\"
[general]
source_profile = false
runfile = \"/path/to/greetd.state\"
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Specific(1),
                    switch: true,
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                    service: "greetd-greeter".to_string(),
                },
                general: ConfigGeneral {
                    multiseat: None,
                    source_profile: false,
                    runfile: "/path/to/greetd.state".to_string(),
                    service: "greetd".to_string(),
                },
                initial_session: None,
            }
        );
    }

    #[test]
    fn invalid_general() {
        assert!(parse_config(
            "
[terminal]\nvt = 1\n[default_session]\ncommand = \"agreety\"
[general]
source_profile = fals
",
        )
        .is_err())
    }

    #[test]
    fn terminal() {
        let config = parse_config(
            "
[default_session]\ncommand = \"agreety\"
[terminal]
vt = 1
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Specific(1),
                    switch: true,
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                    service: "greetd-greeter".to_string(),
                },
                general: Default::default(),
                initial_session: None,
            }
        );
        let config = parse_config(
            "
[default_session]\ncommand = \"agreety\"
[terminal]
vt = next
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Next,
                    switch: true,
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                    service: "greetd-greeter".to_string(),
                },
                general: Default::default(),
                initial_session: None,
            }
        );
        let config = parse_config(
            "
[default_session]\ncommand = \"agreety\"
[terminal]
vt = current
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Current,
                    switch: true,
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                    service: "greetd-greeter".to_string(),
                },
                general: Default::default(),
                initial_session: None,
            }
        );
    }

    #[test]
    fn managed_config_disables_terminal_and_profiles_and_bounds_delegation() {
        let base = "[default_session]\ncommand = \"/usr/libexec/multiseatd/seat-launch /usr/bin/cage -- /usr/bin/regreet\"\n[multiseat]\nseat = \"seat-test\"\ntrusted_entrypoints = \"/usr/bin/sglogin-weston\"\n";
        let config = parse_config(base).unwrap();
        assert_eq!(config.terminal.vt, VtSelection::None);
        assert!(!config.terminal.switch);
        assert!(!config.general.source_profile);
        let settings = config.general.multiseat.unwrap();
        assert_eq!(settings.directory, "/run/greetd-seat-test");
        assert_eq!(settings.vt, 0);
        let mut a = settings.clone();
        a.vt = 7;
        let mut b = settings.clone();
        b.vt = 8;
        assert_ne!(a.instance(), b.instance());
        assert_ne!(a.socket_path(), b.socket_path());
        assert!(parse_config(&format!("{base}vt = 64\n")).is_err());
        assert!(settings
            .arguments(&["/usr/bin/sglogin-weston".into()])
            .is_ok());
        assert!(settings
            .arguments(&["/bin/sh".into(), "-c".into(), "true".into()])
            .is_err());
        assert!(parse_config(&format!("{base}unknown = true\n")).is_err());
        assert!(parse_config(&format!("{base}[terminal]\nvt = 1\n")).is_err());
        assert!(parse_config(&format!("{base}[general]\nsource_profile = true\n")).is_err());
        assert!(parse_config(&base.replace("seat-test", "../../bad")).is_err());
    }

    #[test]
    fn invalid_initial_session() {
        assert!(parse_config(
            "
[terminal]\nvt = 1\n[default_session]\ncommand = \"agreety\"
[initial_session]
"
        )
        .is_err());
        assert!(parse_config(
            "
[terminal]\nvt = 1\n[default_session]\ncommand = \"agreety\"
[initial_session]
command = \"sway\"
"
        )
        .is_err());
        assert!(parse_config(
            "
[terminal]\nvt = 1\n[default_session]\ncommand = \"agreety\"
[initial_session]
user = \"user\"
"
        )
        .is_err());
    }

    #[test]
    fn invalid_default_session() {
        assert!(parse_config(
            "
[terminal]\nvt = 1
[default_session]
"
        )
        .is_err());
        assert!(parse_config(
            "
[terminal]\nvt = 1
[default_session]
user = \"john\"
"
        )
        .is_err());
    }
}

use clap::Parser;
use log::{error, info, warn, LevelFilter};
use simple_logger::SimpleLogger;


/// Inject code into a running process using /proc/pid/mem
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// pid of the target process
    #[arg(short, long)]
    pid: Option<i32>,

    /// target application's package name, (re)start the application and do injection
    #[arg(short, long)]
    app_package_name: Option<String>,

    /// path of the library to inject
    #[arg(short, long)]
    file: String,

    /// function to hijack for injection,
    /// in the form "lib.so!symbol_name"
    #[arg(long)]
    func_sym: Option<String>,

    /// variable to hijack for injection,
    /// in the form "lib.so!symbol_name"
    #[arg(long)]
    var_sym: Option<String>,

    /// enable debug logs
    #[arg(short, long)]
    debug: bool,

    /// print logs to logcat
    #[arg(long)]
    logcat: bool,
}

fn main() {
    let args = Args::parse();

    SimpleLogger::new()
    .with_level(LevelFilter::Debug)
    .init()
    .unwrap();

    let mut target_pid = args.pid.unwrap_or(0);

    #[cfg(target_os = "android")]
    if target_pid <= 0 {
        let Some(name) = args.app_package_name else {
            error!("No pid or app_package_name is specified");
            return;
        };
        let Ok(app_pid) = goauld::Injector::restart_app_and_get_pid(&name) else {
            error!("Can't restart package: {}, or cannot found pid", name);
            return;
        };
        target_pid = app_pid as i32;
    }

    info!("target process pid: {}", target_pid);

    let mut injector = match goauld::Injector::new(target_pid) {
        Ok(injector) => injector,
        Err(e) => {
            error!("Error creating injector: {:?}", e);
            std::process::exit(1);
        }
    };

    
    match injector.set_file_path(args.file) {
        Ok(_) => {}
        Err(e) => {
            error!("Error setting file path: {:?}", e);
            std::process::exit(1);
        }
    }

    match injector.use_raw_dlopen() {
        Ok(_) => {
            info!("use_raw_dlopen successful");
        }
        Err(e) => {
            error!("Error use_raw_dlopen: {:?}", e);
            std::process::exit(1);
        }
    }
    
    if let Some(func_sym) = &args.func_sym {
        let sym_pair: Vec<&str> = func_sym.split('!').collect();
        if sym_pair.len() != 2 {
            error!("Invalid function symbol format, use lib.so!symbol_name");
            std::process::exit(1);
        }
        match injector.set_func_sym(sym_pair[0], sym_pair[1]) {
            Ok(_) => {}
            Err(e) => {
                error!("Error setting function symbol: {:?}", e);
                std::process::exit(1);
            }
        };
    }

    if let Some(var_sym) = &args.var_sym {
        let sym_pair: Vec<&str> = var_sym.split('!').collect();
        if sym_pair.len() != 2 {
            error!("Invalid variable symbol format, use lib.so!symbol_name");
            std::process::exit(1);
        }
        match injector.set_var_sym(sym_pair[0], sym_pair[1]) {
            Ok(_) => {}
            Err(e) => {
                error!("Error setting variable symbol: {:?}", e);
                std::process::exit(1);
            }
        };
    }

    // if either func_sym or var_sym is not provided, use default symbols
    if args.func_sym.is_none() || args.var_sym.is_none() {
        warn!("function or variable symbol not specified, using defaults");
        match injector.set_default_syms() {
            Ok(_) => {}
            Err(e) => {
                error!("Error setting default symbols: {:?}", e);
                std::process::exit(1);
            }
        };
    }

    match injector.inject() {
        Ok(_) => {
            info!("Injection successful");
        }
        Err(e) => {
            error!("Error injecting: {:?}", e);
            std::process::exit(1);
        }
    }
}
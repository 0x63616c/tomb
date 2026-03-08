use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent};

use crate::screens::{generate, home, inspect, open, seal, verify};

// ── Worker messages ─────────────────────────────────────────────────────

pub enum WorkerResult {
    Seal(Result<SealResult, String>),
    Open(Result<OpenResult, String>),
    Verify(Result<(), String>),
}

pub struct SealResult {
    pub output_path: PathBuf,
    pub input_size: u64,
    pub output_size: u64,
}

pub struct OpenResult {
    pub output_path: PathBuf,
}

// ── Screen state ────────────────────────────────────────────────────────

pub enum Screen {
    Home(home::State),
    Seal(seal::State),
    Open(open::State),
    Verify(verify::State),
    Inspect(inspect::State),
    Generate(generate::State),
}

// ── App ─────────────────────────────────────────────────────────────────

pub struct App {
    pub screen: Screen,
    pub worker_rx: Option<mpsc::Receiver<WorkerResult>>,
    pub error: Option<String>,
    pub progress_start: Option<Instant>,
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: Screen::Home(home::State::new()),
            worker_rx: None,
            error: None,
            progress_start: None,
        }
    }

    pub fn go_home(&mut self) {
        self.screen = Screen::Home(home::State::new());
        self.error = None;
        self.progress_start = None;
    }

    pub fn poll_worker(&mut self) {
        let result = self.worker_rx.as_ref().and_then(|rx| rx.try_recv().ok());

        if let Some(result) = result {
            self.worker_rx = None;
            match result {
                WorkerResult::Seal(r) => seal::on_worker_result(self, r),
                WorkerResult::Open(r) => open::on_worker_result(self, r),
                WorkerResult::Verify(r) => verify::on_worker_result(self, r),
            }
        }
    }

    /// Returns true if the app should quit.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Dismiss error with Enter or Esc
        if self.error.is_some() {
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                self.error = None;
            }
            return false;
        }

        // Determine which screen we're on without holding a borrow
        let screen_kind = match &self.screen {
            Screen::Home(_) => 0,
            Screen::Seal(_) => 1,
            Screen::Open(_) => 2,
            Screen::Verify(_) => 3,
            Screen::Inspect(_) => 4,
            Screen::Generate(_) => 5,
        };

        match screen_kind {
            0 => home::handle_key(self, key),
            1 => {
                seal::handle_key(self, key);
                false
            }
            2 => {
                open::handle_key(self, key);
                false
            }
            3 => {
                verify::handle_key(self, key);
                false
            }
            4 => {
                inspect::handle_key(self, key);
                false
            }
            5 => {
                generate::handle_key(self, key);
                false
            }
            _ => false,
        }
    }
}

fn seal_config() -> tomb::SealConfig {
    #[cfg(debug_assertions)]
    if std::env::var("TOMB_TEST_PARAMS").is_ok() {
        return tomb::SealConfig::test();
    }
    tomb::SealConfig::production()
}

pub fn get_config() -> tomb::SealConfig {
    seal_config()
}

use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use tomb::key::Passphrase;

use crate::app::{App, OpenResult, Screen, WorkerResult};
use crate::widgets::passphrase::{render_passphrase_input, PassphraseInput};
use crate::widgets::progress::render_progress;

#[derive(Clone, Copy, PartialEq)]
enum StepKind {
    FilePath,
    Passphrase,
    Opening,
    Done,
}

pub enum Step {
    FilePath,
    Passphrase,
    Opening,
    Done(PathBuf),
}

impl Step {
    fn kind(&self) -> StepKind {
        match self {
            Step::FilePath => StepKind::FilePath,
            Step::Passphrase => StepKind::Passphrase,
            Step::Opening => StepKind::Opening,
            Step::Done(_) => StepKind::Done,
        }
    }
}

pub struct State {
    pub step: Step,
    pub file_path: String,
    pub passphrase: PassphraseInput,
}

impl State {
    pub fn new() -> Self {
        Self {
            step: Step::FilePath,
            file_path: String::new(),
            passphrase: PassphraseInput::new(),
        }
    }
}

fn step_kind(app: &App) -> Option<StepKind> {
    match &app.screen {
        Screen::Open(s) => Some(s.step.kind()),
        _ => None,
    }
}

pub fn handle_key(app: &mut App, key: KeyEvent) {
    let kind = match step_kind(app) {
        Some(k) => k,
        None => return,
    };

    match kind {
        StepKind::FilePath => match key.code {
            KeyCode::Esc => app.go_home(),
            KeyCode::Enter => {
                if let Screen::Open(state) = &mut app.screen {
                    if !state.file_path.is_empty() {
                        let path = PathBuf::from(&state.file_path);
                        if !path.exists() {
                            app.error = Some(format!("File not found: {}", state.file_path));
                        } else {
                            state.step = Step::Passphrase;
                        }
                    }
                }
            }
            KeyCode::Char(c) => {
                if let Screen::Open(state) = &mut app.screen {
                    state.file_path.push(c);
                }
            }
            KeyCode::Backspace => {
                if let Screen::Open(state) = &mut app.screen {
                    state.file_path.pop();
                }
            }
            _ => {}
        },
        StepKind::Passphrase => {
            if key.code == KeyCode::Char('v') && key.modifiers.contains(KeyModifiers::CONTROL) {
                if let Screen::Open(state) = &mut app.screen {
                    state.passphrase.toggle_visibility();
                }
                return;
            }

            match key.code {
                KeyCode::Esc => {
                    if let Screen::Open(state) = &mut app.screen {
                        state.passphrase.clear();
                        state.step = Step::FilePath;
                    }
                }
                KeyCode::Enter => {
                    let is_empty =
                        matches!(&app.screen, Screen::Open(s) if s.passphrase.text.is_empty());
                    if !is_empty {
                        start_open(app);
                    }
                }
                KeyCode::Char(c) => {
                    if let Screen::Open(state) = &mut app.screen {
                        state.passphrase.insert_char(c);
                    }
                }
                KeyCode::Backspace => {
                    if let Screen::Open(state) = &mut app.screen {
                        state.passphrase.backspace();
                    }
                }
                KeyCode::Delete => {
                    if let Screen::Open(state) = &mut app.screen {
                        state.passphrase.delete();
                    }
                }
                _ => {}
            }
        }
        StepKind::Opening => {}
        StepKind::Done => {
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                app.go_home();
            }
        }
    }
}

fn start_open(app: &mut App) {
    let (file_path, pass_text) = match &app.screen {
        Screen::Open(s) => {
            let fp = PathBuf::from(&s.file_path);
            let pt: String = s
                .passphrase
                .text
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            (fp, pt)
        }
        _ => return,
    };

    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let passphrase = Passphrase::new(pass_text.into_bytes());
        let result = tomb::open_file(&file_path, &passphrase);
        let worker_result = match result {
            Ok(opened) => {
                let output_path = PathBuf::from(&opened.filename);
                if output_path.exists() {
                    WorkerResult::Open(Err(format!(
                        "Output file '{}' already exists",
                        output_path.display()
                    )))
                } else {
                    match std::fs::write(&output_path, &opened.data) {
                        Ok(()) => WorkerResult::Open(Ok(OpenResult { output_path })),
                        Err(e) => WorkerResult::Open(Err(format!("{e}"))),
                    }
                }
            }
            Err(e) => WorkerResult::Open(Err(format!("{e}"))),
        };
        let _ = tx.send(worker_result);
    });

    app.worker_rx = Some(rx);
    app.progress_start = Some(Instant::now());

    if let Screen::Open(state) = &mut app.screen {
        state.step = Step::Opening;
    }
}

pub fn on_worker_result(app: &mut App, result: Result<OpenResult, String>) {
    app.progress_start = None;
    match result {
        Ok(open_result) => {
            if let Screen::Open(state) = &mut app.screen {
                state.step = Step::Done(open_result.output_path);
            }
        }
        Err(e) => {
            app.error = Some(e);
            if let Screen::Open(state) = &mut app.screen {
                state.step = Step::Passphrase;
                state.passphrase.clear();
            }
        }
    }
}

pub fn status_hint(state: &State) -> &'static str {
    match &state.step {
        Step::FilePath => "Enter: next  Esc: back",
        Step::Passphrase => "Enter: open  Ctrl+V: toggle  Esc: back",
        Step::Opening => "Opening in progress...",
        Step::Done(_) => "Enter/Esc: home",
    }
}

pub fn render(frame: &mut Frame, area: Rect, state: &State, app: &App) {
    let padded = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(area);
    let content = padded[1];

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(1)])
        .split(content);

    let title = Paragraph::new(Line::from(Span::styled(
        "Open a .tomb File",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    frame.render_widget(title, vertical[0]);

    let body = vertical[1];

    match &state.step {
        Step::FilePath => {
            render_text_input(frame, body, "File path (.tomb):", &state.file_path);
        }
        Step::Passphrase => {
            render_passphrase_input(frame, body, &state.passphrase, "Enter passphrase:");
        }
        Step::Opening => {
            render_progress(frame, body, "Opening...", app.progress_start);
        }
        Step::Done(path) => {
            let lines = vec![
                Line::from(Span::styled(
                    "Opened successfully!",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Output: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        path.display().to_string(),
                        Style::default().fg(Color::White),
                    ),
                ]),
            ];
            let paragraph = Paragraph::new(lines);
            frame.render_widget(paragraph, body);
        }
    }
}

fn render_text_input(frame: &mut Frame, area: Rect, label: &str, value: &str) {
    let lines = vec![
        Line::from(Span::styled(label, Style::default().fg(Color::Cyan))),
        Line::from(""),
        Line::from(Span::styled(
            if value.is_empty() {
                "(type here)"
            } else {
                value
            },
            if value.is_empty() {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(Color::White)
            },
        )),
    ];

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, area);

    frame.set_cursor_position(Position::new(area.x + value.len() as u16, area.y + 2));
}

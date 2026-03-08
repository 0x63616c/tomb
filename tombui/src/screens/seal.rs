use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use tomb::key::Passphrase;
use tomb::passphrase::generate::generate_passphrase;
use tomb::passphrase::validate_passphrase;

use crate::app::{self, App, Screen, SealResult, WorkerResult};
use crate::widgets::passphrase::{render_passphrase_input, PassphraseInput};
use crate::widgets::progress::render_progress;

#[derive(Clone, Copy, PartialEq)]
enum StepKind {
    FilePath,
    Note,
    Passphrase,
    ConfirmPassphrase,
    ShowGenerated,
    Sealing,
    Done,
}

pub enum Step {
    FilePath,
    Note,
    Passphrase,
    ConfirmPassphrase,
    ShowGenerated,
    Sealing,
    Done(DoneInfo),
}

impl Step {
    fn kind(&self) -> StepKind {
        match self {
            Step::FilePath => StepKind::FilePath,
            Step::Note => StepKind::Note,
            Step::Passphrase => StepKind::Passphrase,
            Step::ConfirmPassphrase => StepKind::ConfirmPassphrase,
            Step::ShowGenerated => StepKind::ShowGenerated,
            Step::Sealing => StepKind::Sealing,
            Step::Done(_) => StepKind::Done,
        }
    }
}

pub struct DoneInfo {
    pub output_path: PathBuf,
    pub input_size: u64,
    pub output_size: u64,
}

pub struct State {
    pub step: Step,
    pub file_path: String,
    pub note: String,
    pub passphrase: PassphraseInput,
    pub confirm: PassphraseInput,
    pub generated_words: Option<Vec<String>>,
}

impl State {
    pub fn new() -> Self {
        Self {
            step: Step::FilePath,
            file_path: String::new(),
            note: String::new(),
            passphrase: PassphraseInput::new(),
            confirm: PassphraseInput::new(),
            generated_words: None,
        }
    }
}

fn step_kind(app: &App) -> Option<StepKind> {
    match &app.screen {
        Screen::Seal(s) => Some(s.step.kind()),
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
                if let Screen::Seal(state) = &mut app.screen {
                    if !state.file_path.is_empty() {
                        let path = PathBuf::from(&state.file_path);
                        if !path.exists() {
                            app.error = Some(format!("File not found: {}", state.file_path));
                        } else {
                            state.step = Step::Note;
                        }
                    }
                }
            }
            KeyCode::Char(c) => {
                if let Screen::Seal(state) = &mut app.screen {
                    state.file_path.push(c);
                }
            }
            KeyCode::Backspace => {
                if let Screen::Seal(state) = &mut app.screen {
                    state.file_path.pop();
                }
            }
            _ => {}
        },
        StepKind::Note => {
            if let Screen::Seal(state) = &mut app.screen {
                match key.code {
                    KeyCode::Esc => state.step = Step::FilePath,
                    KeyCode::Enter => state.step = Step::Passphrase,
                    KeyCode::Char(c) => state.note.push(c),
                    KeyCode::Backspace => {
                        state.note.pop();
                    }
                    _ => {}
                }
            }
        }
        StepKind::Passphrase => {
            if key.code == KeyCode::Char('v') && key.modifiers.contains(KeyModifiers::CONTROL) {
                if let Screen::Seal(state) = &mut app.screen {
                    state.passphrase.toggle_visibility();
                }
                return;
            }

            match key.code {
                KeyCode::Esc => {
                    if let Screen::Seal(state) = &mut app.screen {
                        state.step = Step::Note;
                    }
                }
                KeyCode::Enter => {
                    if let Screen::Seal(state) = &mut app.screen {
                        if state.passphrase.text.is_empty() {
                            let words = generate_passphrase(21);
                            state.generated_words = Some(words);
                            state.step = Step::ShowGenerated;
                        } else {
                            match validate_passphrase(&state.passphrase.text) {
                                Ok(()) => state.step = Step::ConfirmPassphrase,
                                Err(e) => app.error = Some(format!("{e}")),
                            }
                        }
                    }
                }
                KeyCode::Char(c) => {
                    if let Screen::Seal(state) = &mut app.screen {
                        state.passphrase.insert_char(c);
                    }
                }
                KeyCode::Backspace => {
                    if let Screen::Seal(state) = &mut app.screen {
                        state.passphrase.backspace();
                    }
                }
                KeyCode::Delete => {
                    if let Screen::Seal(state) = &mut app.screen {
                        state.passphrase.delete();
                    }
                }
                _ => {}
            }
        }
        StepKind::ConfirmPassphrase => {
            if key.code == KeyCode::Char('v') && key.modifiers.contains(KeyModifiers::CONTROL) {
                if let Screen::Seal(state) = &mut app.screen {
                    state.confirm.toggle_visibility();
                }
                return;
            }

            match key.code {
                KeyCode::Esc => {
                    if let Screen::Seal(state) = &mut app.screen {
                        state.confirm.clear();
                        state.step = Step::Passphrase;
                    }
                }
                KeyCode::Enter => {
                    // Extract data we need before mutating
                    let pass_norm = if let Screen::Seal(state) = &app.screen {
                        if let Some(words) = &state.generated_words {
                            words.join(" ")
                        } else {
                            state
                                .passphrase
                                .text
                                .split_whitespace()
                                .collect::<Vec<_>>()
                                .join(" ")
                        }
                    } else {
                        return;
                    };

                    let conf_norm = if let Screen::Seal(state) = &app.screen {
                        state
                            .confirm
                            .text
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ")
                    } else {
                        return;
                    };

                    if pass_norm != conf_norm {
                        app.error = Some("Passphrases do not match".into());
                        if let Screen::Seal(state) = &mut app.screen {
                            state.confirm.clear();
                        }
                    } else {
                        start_seal(app, pass_norm);
                    }
                }
                KeyCode::Char(c) => {
                    if let Screen::Seal(state) = &mut app.screen {
                        state.confirm.insert_char(c);
                    }
                }
                KeyCode::Backspace => {
                    if let Screen::Seal(state) = &mut app.screen {
                        state.confirm.backspace();
                    }
                }
                KeyCode::Delete => {
                    if let Screen::Seal(state) = &mut app.screen {
                        state.confirm.delete();
                    }
                }
                _ => {}
            }
        }
        StepKind::ShowGenerated => {
            if let Screen::Seal(state) = &mut app.screen {
                match key.code {
                    KeyCode::Esc => {
                        state.generated_words = None;
                        state.step = Step::Passphrase;
                    }
                    KeyCode::Enter => {
                        state.confirm.clear();
                        state.step = Step::ConfirmPassphrase;
                    }
                    _ => {}
                }
            }
        }
        StepKind::Sealing => {}
        StepKind::Done => {
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                app.go_home();
            }
        }
    }
}

fn start_seal(app: &mut App, passphrase_text: String) {
    let (file_path, note) = match &app.screen {
        Screen::Seal(s) => {
            let fp = PathBuf::from(&s.file_path);
            let n = if s.note.is_empty() {
                None
            } else {
                Some(s.note.clone())
            };
            (fp, n)
        }
        _ => return,
    };

    let mut output_path = file_path.clone();
    output_path.set_extension("tomb");

    let config = app::get_config();
    let (tx, rx) = mpsc::channel();

    let out = output_path;
    let fp = file_path;
    let n = note;

    thread::spawn(move || {
        let passphrase = Passphrase::new(passphrase_text.into_bytes());
        let result = tomb::seal(&fp, &out, &passphrase, n.as_deref(), &config);
        let worker_result = match result {
            Ok(()) => {
                let input_size = std::fs::metadata(&fp).map(|m| m.len()).unwrap_or(0);
                let output_size = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
                WorkerResult::Seal(Ok(SealResult {
                    output_path: out,
                    input_size,
                    output_size,
                }))
            }
            Err(e) => WorkerResult::Seal(Err(format!("{e}"))),
        };
        let _ = tx.send(worker_result);
    });

    app.worker_rx = Some(rx);
    app.progress_start = Some(Instant::now());

    if let Screen::Seal(state) = &mut app.screen {
        state.step = Step::Sealing;
    }
}

pub fn on_worker_result(app: &mut App, result: Result<SealResult, String>) {
    app.progress_start = None;
    match result {
        Ok(seal_result) => {
            if let Screen::Seal(state) = &mut app.screen {
                state.step = Step::Done(DoneInfo {
                    output_path: seal_result.output_path,
                    input_size: seal_result.input_size,
                    output_size: seal_result.output_size,
                });
            }
        }
        Err(e) => {
            app.error = Some(e);
            if let Screen::Seal(state) = &mut app.screen {
                state.step = Step::Passphrase;
                state.passphrase.clear();
                state.confirm.clear();
            }
        }
    }
}

pub fn status_hint(state: &State) -> &'static str {
    match &state.step {
        Step::FilePath => "Enter: next  Esc: back",
        Step::Note => "Enter: next (empty for no note)  Esc: back",
        Step::Passphrase => "Enter: next (empty to generate)  Ctrl+V: toggle  Esc: back",
        Step::ConfirmPassphrase => "Enter: confirm  Ctrl+V: toggle  Esc: back",
        Step::ShowGenerated => "Enter: continue to re-entry  Esc: back",
        Step::Sealing => "Sealing in progress...",
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
        "Seal a File",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    frame.render_widget(title, vertical[0]);

    let body = vertical[1];

    match &state.step {
        Step::FilePath => {
            render_text_input(frame, body, "File path:", &state.file_path);
        }
        Step::Note => {
            render_text_input(
                frame,
                body,
                "Note (optional, press Enter to skip):",
                &state.note,
            );
        }
        Step::Passphrase => {
            render_passphrase_input(
                frame,
                body,
                &state.passphrase,
                "Enter passphrase (or press Enter to generate):",
            );
        }
        Step::ConfirmPassphrase => {
            render_passphrase_input(frame, body, &state.confirm, "Confirm passphrase:");
        }
        Step::ShowGenerated => {
            render_generated(frame, body, state.generated_words.as_deref().unwrap_or(&[]));
        }
        Step::Sealing => {
            render_progress(frame, body, "Sealing...", app.progress_start);
        }
        Step::Done(info) => {
            render_done(frame, body, info);
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

fn render_generated(frame: &mut Frame, area: Rect, words: &[String]) {
    let mut lines = vec![
        Line::from(Span::styled(
            "Your passphrase (21 words):",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    for chunk in words.chunks(7) {
        let word_line = chunk.join("  ");
        lines.push(Line::from(Span::styled(
            format!("  {word_line}"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Write this down somewhere safe.",
        Style::default().fg(Color::White),
    )));
    lines.push(Line::from(Span::styled(
        "Press Enter when ready to re-enter it.",
        Style::default().fg(Color::DarkGray),
    )));

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, area);
}

fn render_done(frame: &mut Frame, area: Rect, info: &DoneInfo) {
    let overhead = info.output_size as i64 - info.input_size as i64;
    let sign = if overhead >= 0 { "+" } else { "" };

    let lines = vec![
        Line::from(Span::styled(
            "Sealed successfully!",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Output: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                info.output_path.display().to_string(),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("Size: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!(
                    "{} bytes (was {} bytes, {sign}{overhead} bytes)",
                    info.output_size, info.input_size
                ),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Remember to delete the original file.",
            Style::default().fg(Color::Yellow),
        )),
    ];

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, area);
}

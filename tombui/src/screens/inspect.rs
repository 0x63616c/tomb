use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::Frame;

use tomb::format::PublicHeader;

use crate::app::{App, Screen};
use crate::widgets::header::render_header;

#[derive(Clone, Copy, PartialEq)]
enum StepKind {
    FilePath,
    ShowHeader,
}

pub enum Step {
    FilePath,
    ShowHeader(PublicHeader),
}

impl Step {
    fn kind(&self) -> StepKind {
        match self {
            Step::FilePath => StepKind::FilePath,
            Step::ShowHeader(_) => StepKind::ShowHeader,
        }
    }
}

pub struct State {
    pub step: Step,
    pub file_path: String,
}

impl State {
    pub fn new() -> Self {
        Self {
            step: Step::FilePath,
            file_path: String::new(),
        }
    }
}

fn step_kind(app: &App) -> Option<StepKind> {
    match &app.screen {
        Screen::Inspect(s) => Some(s.step.kind()),
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
                if let Screen::Inspect(state) = &mut app.screen {
                    if !state.file_path.is_empty() {
                        let path = PathBuf::from(&state.file_path);
                        if !path.exists() {
                            app.error = Some(format!("File not found: {}", state.file_path));
                        } else {
                            match tomb::inspect_file(&path) {
                                Ok(header) => state.step = Step::ShowHeader(header),
                                Err(e) => app.error = Some(format!("{e}")),
                            }
                        }
                    }
                }
            }
            KeyCode::Char(c) => {
                if let Screen::Inspect(state) = &mut app.screen {
                    state.file_path.push(c);
                }
            }
            KeyCode::Backspace => {
                if let Screen::Inspect(state) = &mut app.screen {
                    state.file_path.pop();
                }
            }
            _ => {}
        },
        StepKind::ShowHeader => {
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                app.go_home();
            }
        }
    }
}

pub fn status_hint(state: &State) -> &'static str {
    match &state.step {
        Step::FilePath => "Enter: inspect  Esc: back",
        Step::ShowHeader(_) => "Esc/Enter/q: home",
    }
}

pub fn render(frame: &mut Frame, area: Rect, state: &State) {
    match &state.step {
        Step::FilePath => {
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

            let title = ratatui::widgets::Paragraph::new(Line::from(Span::styled(
                "Inspect a .tomb File",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
            frame.render_widget(title, vertical[0]);

            render_text_input(frame, vertical[1], "File path (.tomb):", &state.file_path);
        }
        Step::ShowHeader(header) => {
            render_header(frame, area, &state.file_path, header);
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

    let paragraph = ratatui::widgets::Paragraph::new(lines);
    frame.render_widget(paragraph, area);

    frame.set_cursor_position(Position::new(area.x + value.len() as u16, area.y + 2));
}

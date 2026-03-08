use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use tomb::passphrase::generate::generate_passphrase;

use crate::app::{App, Screen};
use crate::widgets::passphrase::{render_passphrase_input, PassphraseInput};

pub enum Step {
    ShowPassphrase,
    Confirm,
    Done,
}

pub struct State {
    pub step: Step,
    pub words: Vec<String>,
    pub confirm: PassphraseInput,
}

impl State {
    pub fn new() -> Self {
        Self {
            step: Step::ShowPassphrase,
            words: generate_passphrase(21),
            confirm: PassphraseInput::new(),
        }
    }
}

pub fn handle_key(app: &mut App, key: KeyEvent) {
    let state = match &mut app.screen {
        Screen::Generate(s) => s,
        _ => return,
    };

    match &state.step {
        Step::ShowPassphrase => match key.code {
            KeyCode::Esc => app.go_home(),
            KeyCode::Enter => state.step = Step::Confirm,
            _ => {}
        },
        Step::Confirm => {
            if key.code == KeyCode::Char('v') && key.modifiers.contains(KeyModifiers::CONTROL) {
                state.confirm.toggle_visibility();
                return;
            }

            match key.code {
                KeyCode::Esc => {
                    state.confirm.clear();
                    state.step = Step::ShowPassphrase;
                }
                KeyCode::Enter => {
                    let generated = state.words.join(" ");
                    let entered: String = state
                        .confirm
                        .text
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");

                    if entered == generated {
                        state.step = Step::Done;
                    } else {
                        app.error = Some("Passphrases do not match. Try again.".into());
                        state.confirm.clear();
                    }
                }
                KeyCode::Char(c) => state.confirm.insert_char(c),
                KeyCode::Backspace => state.confirm.backspace(),
                KeyCode::Delete => state.confirm.delete(),
                _ => {}
            }
        }
        Step::Done => {
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                app.go_home();
            }
        }
    }
}

pub fn status_hint(state: &State) -> &'static str {
    match &state.step {
        Step::ShowPassphrase => "Enter: continue to re-entry  Esc: back",
        Step::Confirm => "Enter: confirm  Ctrl+V: toggle  Esc: back",
        Step::Done => "Enter/Esc: home",
    }
}

pub fn render(frame: &mut Frame, area: Rect, state: &State) {
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
        "Generate a Passphrase",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    frame.render_widget(title, vertical[0]);

    let body = vertical[1];

    match &state.step {
        Step::ShowPassphrase => {
            let mut lines = vec![
                Line::from(Span::styled(
                    "Your passphrase (21 words):",
                    Style::default().fg(Color::White),
                )),
                Line::from(""),
            ];

            for chunk in state.words.chunks(7) {
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
            frame.render_widget(paragraph, body);
        }
        Step::Confirm => {
            render_passphrase_input(
                frame,
                body,
                &state.confirm,
                "Re-enter your passphrase to confirm:",
            );
        }
        Step::Done => {
            let lines = vec![
                Line::from(Span::styled(
                    "Match confirmed!",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Your passphrase has been verified.",
                    Style::default().fg(Color::White),
                )),
            ];
            let paragraph = Paragraph::new(lines);
            frame.render_widget(paragraph, body);
        }
    }
}

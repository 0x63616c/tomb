use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{App, Screen};
use crate::screens::{generate, inspect, open, seal, verify};

const MENU_ITEMS: &[&str] = &[
    "Seal a file",
    "Open a .tomb file",
    "Verify a .tomb file",
    "Inspect a .tomb file",
    "Generate a passphrase",
];

pub struct State {
    pub selected: usize,
}

impl State {
    pub fn new() -> Self {
        Self { selected: 0 }
    }
}

/// Returns true if the app should quit.
pub fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    let selected = match &app.screen {
        Screen::Home(state) => state.selected,
        _ => return false,
    };

    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('j') | KeyCode::Down => {
            if let Screen::Home(state) = &mut app.screen {
                state.selected = (state.selected + 1) % MENU_ITEMS.len();
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if let Screen::Home(state) = &mut app.screen {
                state.selected = state
                    .selected
                    .checked_sub(1)
                    .unwrap_or(MENU_ITEMS.len() - 1);
            }
        }
        KeyCode::Enter => match selected {
            0 => app.screen = Screen::Seal(seal::State::new()),
            1 => app.screen = Screen::Open(open::State::new()),
            2 => app.screen = Screen::Verify(verify::State::new()),
            3 => app.screen = Screen::Inspect(inspect::State::new()),
            4 => app.screen = Screen::Generate(generate::State::new()),
            _ => {}
        },
        _ => {}
    }
    false
}

pub fn render(frame: &mut Frame, area: Rect, state: &State) {
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "tomb - encrypt anything",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    for (i, item) in MENU_ITEMS.iter().enumerate() {
        let prefix = if i == state.selected { "> " } else { "  " };
        let style = if i == state.selected {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(Span::styled(format!("{prefix}{item}"), style)));
    }

    let paragraph = Paragraph::new(lines).alignment(Alignment::Center);

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Min(10),
            Constraint::Percentage(30),
        ])
        .split(area);

    frame.render_widget(paragraph, vertical[1]);
}

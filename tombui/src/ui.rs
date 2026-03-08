use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::{App, Screen};
use crate::screens::{generate, home, inspect, open, seal, verify};

pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Split into main content and status bar
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(area);

    let main_area = chunks[0];
    let status_area = chunks[1];

    // Render the current screen
    match &app.screen {
        Screen::Home(state) => home::render(frame, main_area, state),
        Screen::Seal(state) => seal::render(frame, main_area, state, app),
        Screen::Open(state) => open::render(frame, main_area, state, app),
        Screen::Verify(state) => verify::render(frame, main_area, state, app),
        Screen::Inspect(state) => inspect::render(frame, main_area, state),
        Screen::Generate(state) => generate::render(frame, main_area, state),
    }

    // Status bar
    let status_text = match &app.screen {
        Screen::Home(_) => "j/k: move  Enter: select  q: quit",
        Screen::Seal(state) => seal::status_hint(state),
        Screen::Open(state) => open::status_hint(state),
        Screen::Verify(state) => verify::status_hint(state),
        Screen::Inspect(state) => inspect::status_hint(state),
        Screen::Generate(state) => generate::status_hint(state),
    };

    let status = Paragraph::new(status_text).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(status, status_area);

    // Error overlay
    if let Some(err) = &app.error {
        let error_block = Block::default()
            .title(" Error ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red));
        let error_text = Paragraph::new(format!("{err}\n\nPress Enter or Esc to dismiss"))
            .block(error_block)
            .style(Style::default().fg(Color::Red));

        let error_area = centered_rect(60, 20, area);
        frame.render_widget(ratatui::widgets::Clear, error_area);
        frame.render_widget(error_text, error_area);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

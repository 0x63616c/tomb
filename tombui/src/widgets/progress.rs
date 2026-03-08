use std::time::Instant;

use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

const SPINNER_FRAMES: &[&str] = &["|", "/", "-", "\\"];

pub fn render_progress(frame: &mut Frame, area: Rect, label: &str, start: Option<Instant>) {
    let elapsed = start.map(|s| s.elapsed().as_secs()).unwrap_or(0);

    let spinner_idx = start
        .map(|s| (s.elapsed().as_millis() / 100) as usize % SPINNER_FRAMES.len())
        .unwrap_or(0);
    let spinner = SPINNER_FRAMES[spinner_idx];

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("{spinner} {label}"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("Elapsed: {elapsed}s"),
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let paragraph = Paragraph::new(lines).alignment(Alignment::Center);

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Min(6),
            Constraint::Percentage(30),
        ])
        .split(area);

    frame.render_widget(paragraph, vertical[1]);
}

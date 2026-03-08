use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use tomb::format::PublicHeader;

pub fn render_header(frame: &mut Frame, area: Rect, file_path: &str, header: &PublicHeader) {
    let mut lines = vec![
        Line::from(Span::styled(
            "Inspect",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("File: ", Style::default().fg(Color::DarkGray)),
            Span::styled(file_path, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Format: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("v{}.{}", header.version_major, header.version_minor),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            format!("KDF Chain ({} stages):", header.kdf_chain.len()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
    ];

    for (i, kdf) in header.kdf_chain.iter().enumerate() {
        let id = kdf.id();
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {}. ", i + 1),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("{} (0x{:02x})", id.name(), id as u8),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(
                format!("  {}", kdf.memory_display()),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("Cipher Layers ({}):", header.layers.len()),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));

    for (i, layer) in header.layers.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {}. ", i + 1),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("{} (0x{:02x})", layer.id.name(), layer.id as u8),
                Style::default().fg(Color::Green),
            ),
            Span::styled(
                format!("  nonce: {} bytes", layer.nonce_size),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }

    let paragraph = Paragraph::new(lines);

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

    let padded = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(vertical[1]);

    frame.render_widget(paragraph, padded[1]);
}

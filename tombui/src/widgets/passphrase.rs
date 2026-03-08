use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

pub struct PassphraseInput {
    pub text: String,
    pub visible: bool,
    pub cursor: usize,
}

impl PassphraseInput {
    pub fn new() -> Self {
        Self {
            text: String::new(),
            visible: false,
            cursor: 0,
        }
    }

    pub fn insert_char(&mut self, c: char) {
        self.text.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            let prev = self.text[..self.cursor]
                .char_indices()
                .last()
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.text.remove(prev);
            self.cursor = prev;
        }
    }

    pub fn delete(&mut self) {
        if self.cursor < self.text.len() {
            self.text.remove(self.cursor);
        }
    }

    pub fn toggle_visibility(&mut self) {
        self.visible = !self.visible;
    }

    pub fn word_count(&self) -> usize {
        self.text.split_whitespace().count()
    }

    pub fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
    }
}

impl Drop for PassphraseInput {
    fn drop(&mut self) {
        // Zero out the passphrase memory
        unsafe {
            let bytes = self.text.as_bytes_mut();
            for b in bytes.iter_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

pub fn render_passphrase_input(
    frame: &mut Frame,
    area: Rect,
    input: &PassphraseInput,
    label: &str,
) {
    let display = if input.visible {
        input.text.clone()
    } else if input.text.is_empty() {
        String::new()
    } else {
        "* ".repeat(input.word_count()).trim_end().to_string()
    };

    let word_info = format!(" ({}/21 words)", input.word_count());
    let visibility_hint = if input.visible {
        " [Ctrl+V: hide]"
    } else {
        " [Ctrl+V: show]"
    };

    let lines = vec![
        Line::from(Span::styled(label, Style::default().fg(Color::Cyan))),
        Line::from(""),
        Line::from(Span::styled(
            if display.is_empty() {
                "(type your passphrase)".to_string()
            } else {
                display
            },
            if input.text.is_empty() {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(Color::White)
            },
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(word_info, Style::default().fg(Color::DarkGray)),
            Span::styled(visibility_hint, Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, area);

    // Show cursor
    let cursor_x = if input.visible {
        area.x + input.cursor as u16
    } else if input.text.is_empty() {
        area.x
    } else {
        area.x + (input.word_count() * 2).saturating_sub(1) as u16
    };
    frame.set_cursor_position(Position::new(cursor_x, area.y + 2));
}

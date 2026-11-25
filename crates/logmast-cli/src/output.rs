//! What a command prints: short text for a person at a terminal, stable JSON for
//! agents, scripts and pipes. Secrets never reach either form.
use serde_json::Value;
use std::io::IsTerminal;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Text on a terminal, JSON otherwise.
    Auto,
    Human,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
}

impl OutputFormat {
    pub fn mode(self) -> OutputMode {
        match self {
            OutputFormat::Human => OutputMode::Human,
            OutputFormat::Json => OutputMode::Json,
            OutputFormat::Auto if std::io::stdout().is_terminal() => OutputMode::Human,
            OutputFormat::Auto => OutputMode::Json,
        }
    }
}

/// A command's result in both forms. `human` is `None` where the JSON itself is the
/// most useful text, and is then printed indented.
pub struct Report {
    pub json: Value,
    pub human: Option<String>,
}

impl Report {
    pub fn json(json: Value) -> Self {
        Self { json, human: None }
    }
    pub fn with_text(json: Value, human: String) -> Self {
        Self {
            json,
            human: Some(human),
        }
    }
    pub fn render(&self, mode: OutputMode) -> String {
        match (mode, &self.human) {
            (OutputMode::Human, Some(text)) => text.clone(),
            (OutputMode::Human, None) => {
                serde_json::to_string_pretty(&self.json).unwrap_or_else(|_| self.json.to_string())
            }
            (OutputMode::Json, _) => self.json.to_string(),
        }
    }
}

/// A failure as printed on stderr: the error, its stable code, and the next step.
pub fn render_failure(mode: OutputMode, code: &str, message: &str, next_step: &str) -> String {
    match mode {
        OutputMode::Human => format!("error: {message}\nnext: {next_step}"),
        OutputMode::Json => {
            serde_json::json!({"version":1,"code":code,"error":message,"next":next_step})
                .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn people_read_text_and_programs_read_the_same_facts_as_json() {
        let report = Report::with_text(json!({"service_id":"s1"}), "Created service api.".into());
        assert_eq!(report.render(OutputMode::Human), "Created service api.");
        assert_eq!(report.render(OutputMode::Json), r#"{"service_id":"s1"}"#);
        assert_eq!(
            Report::json(json!({"a":1})).render(OutputMode::Human),
            "{\n  \"a\": 1\n}"
        );
    }

    #[test]
    fn a_failure_names_its_code_and_next_step_in_both_forms() {
        assert_eq!(
            render_failure(
                OutputMode::Human,
                "PERMISSION_DENIED",
                "refused",
                "ask an owner"
            ),
            "error: refused\nnext: ask an owner"
        );
        assert_eq!(
            render_failure(
                OutputMode::Json,
                "PERMISSION_DENIED",
                "refused",
                "ask an owner"
            ),
            r#"{"code":"PERMISSION_DENIED","error":"refused","next":"ask an owner","version":1}"#
        );
    }
}

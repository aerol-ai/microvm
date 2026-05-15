use std::fmt::Write as _;

#[derive(Debug, Clone)]
pub struct Image {
    dockerfile: String,
    error: Option<String>,
}

impl Image {
    pub fn base(image: &str) -> Self {
        let trimmed = image.trim();
        if trimmed.is_empty() {
            return Self::with_error("Image::base requires a non-empty image string");
        }
        Self {
            dockerfile: format!("FROM {}\n", trimmed),
            error: None,
        }
    }

    pub fn from_dockerfile(dockerfile: &str) -> Self {
        if dockerfile.trim().is_empty() {
            return Self::with_error(
                "Image::from_dockerfile requires a non-empty Dockerfile string",
            );
        }
        let mut value = dockerfile.to_string();
        if !value.ends_with('\n') {
            value.push('\n');
        }
        Self {
            dockerfile: value,
            error: None,
        }
    }

    pub fn dockerfile(&self) -> &str {
        &self.dockerfile
    }

    pub(crate) fn validation_error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn run_command(mut self, command: &str) -> Self {
        if self.error.is_some() {
            return self;
        }
        let trimmed = command.trim();
        if !trimmed.is_empty() {
            let _ = writeln!(self.dockerfile, "RUN {}", trimmed);
        }
        self
    }

    pub fn run_commands<I, S>(mut self, commands: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if self.error.is_some() {
            return self;
        }
        for command in commands {
            let trimmed = command.as_ref().trim();
            if !trimmed.is_empty() {
                let _ = writeln!(self.dockerfile, "RUN {}", trimmed);
            }
        }
        self
    }

    pub fn run_command_group<I, S>(mut self, commands: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if self.error.is_some() {
            return self;
        }
        let joined = commands
            .into_iter()
            .map(|command| command.as_ref().trim().to_string())
            .filter(|command| !command.is_empty())
            .collect::<Vec<_>>()
            .join(" && ");
        if !joined.is_empty() {
            let _ = writeln!(self.dockerfile, "RUN {}", joined);
        }
        self
    }

    pub fn env<I, K, V>(mut self, env_vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        if self.error.is_some() {
            return self;
        }
        let mut pairs = env_vars
            .into_iter()
            .map(|(key, value)| (key.as_ref().to_string(), value.as_ref().to_string()))
            .collect::<Vec<_>>();
        pairs.sort_by(|left, right| left.0.cmp(&right.0));
        if !pairs.is_empty() {
            let joined = pairs
                .into_iter()
                .map(|(key, value)| format!("{}={}", key, docker_quote(&value)))
                .collect::<Vec<_>>()
                .join(" ");
            let _ = writeln!(self.dockerfile, "ENV {}", joined);
        }
        self
    }

    pub fn workdir(mut self, dir_path: &str) -> Self {
        if self.error.is_some() {
            return self;
        }
        if dir_path.trim().is_empty() {
            return self.record_error("Image::workdir requires a non-empty path");
        }
        let _ = writeln!(self.dockerfile, "WORKDIR {}", dir_path);
        self
    }

    pub fn entrypoint<I, S>(mut self, commands: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if self.error.is_some() {
            return self;
        }
        match json_exec_form(commands) {
            Ok(payload) => {
                let _ = writeln!(self.dockerfile, "ENTRYPOINT {}", payload);
                self
            }
            Err(err) => self.record_error(format!("encode entrypoint: {}", err)),
        }
    }

    pub fn cmd<I, S>(mut self, commands: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if self.error.is_some() {
            return self;
        }
        match json_exec_form(commands) {
            Ok(payload) => {
                let _ = writeln!(self.dockerfile, "CMD {}", payload);
                self
            }
            Err(err) => self.record_error(format!("encode cmd: {}", err)),
        }
    }

    pub fn user(mut self, username: &str) -> Self {
        if self.error.is_some() {
            return self;
        }
        if username.trim().is_empty() {
            return self.record_error("Image::user requires a non-empty username");
        }
        let _ = writeln!(self.dockerfile, "USER {}", username);
        self
    }

    pub fn expose(mut self, port: u32) -> Self {
        if self.error.is_some() {
            return self;
        }
        if !(1..=65535).contains(&port) {
            return self.record_error(format!("Image::expose: port {} is out of range", port));
        }
        let _ = writeln!(self.dockerfile, "EXPOSE {}", port);
        self
    }

    fn with_error(message: &str) -> Self {
        Self {
            dockerfile: String::new(),
            error: Some(message.to_string()),
        }
    }

    fn record_error(mut self, message: impl Into<String>) -> Self {
        if self.error.is_none() {
            self.error = Some(message.into());
        }
        self
    }
}

fn docker_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | '@'))
    {
        return value.to_string();
    }
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn json_exec_form<I, S>(parts: I) -> Result<String, serde_json::Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let values = parts
        .into_iter()
        .map(|part| part.as_ref().to_string())
        .collect::<Vec<_>>();
    serde_json::to_string(&values)
}

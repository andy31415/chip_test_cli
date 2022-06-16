use std::time::Duration;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Command {
    List,
    Scan(Duration),
    Help,
    Exit,
}


impl Command {
    pub fn all_strings() -> Vec<String> {
        vec![
            "exit".to_string(),
            "help".to_string(),
            "list".to_string(),
            "scan".to_string(),
        ]
    }
}

use std::time::Duration;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Command {
    List,
    Scan(Duration),
    Exit,
}


impl Command {
    pub fn all_strings() -> Vec<String> {
        vec![
            "list".to_string(),
            "scan".to_string(),
            "exit".to_string(),
        ]
    }
}

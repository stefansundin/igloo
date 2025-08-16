use std::{fs, time::UNIX_EPOCH};

pub fn humanize_duration(seconds: u64) -> String {
  if seconds == 1 {
    return "1 second".to_string();
  } else if seconds < 60 {
    return format!("{} seconds", seconds);
  }

  let minutes = seconds / 60;
  if minutes == 1 {
    return "1 minute".to_string();
  } else if minutes < 60 {
    return format!("{} minutes", minutes);
  }

  let hours = minutes / 60;
  if hours == 1 {
    return "1 hour".to_string();
  } else if hours < 24 {
    return format!("{} hours", hours);
  } else if hours == 25 {
    return "1 day 1 hour".to_string();
  } else if hours < 48 {
    return format!("1 day {} hours", hours - 24);
  }

  let days = hours / 24;
  return format!("{} days", days);
}

pub fn get_file_mtime(path: &str) -> Option<u64> {
  fs::metadata(path)
    .and_then(|metadata| metadata.modified())
    .ok()
    .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
    .map(|duration| duration.as_secs())
}

pub fn includes_host(host: &Option<&str>, vec: &Vec<&str>) -> bool {
  return host.is_some_and(|host| {
    vec.iter().any(|name| {
      if name.starts_with("*.") {
        host.ends_with(&name[1..])
      } else {
        host == *name
      }
    })
  });
}

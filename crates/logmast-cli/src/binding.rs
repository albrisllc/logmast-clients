//! Which workspace and project a directory works with, recorded by `logmastctl setup`
//! in the CLI's own configuration, so nothing is written into the repository. The
//! nearest enclosing bound directory wins. Bindings hold identifiers, not secrets.
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const BINDINGS_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub directory: PathBuf,
    pub origin: String,
    pub workspace: Uuid,
    pub project: Option<Uuid>,
}

// Unknown fields are ignored, so a newer CLI's additions never break an older one.
#[derive(Debug, Serialize, Deserialize)]
struct BindingFile {
    version: u32,
    bindings: Vec<Binding>,
}

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("the directory bindings file {path} cannot be read or written")]
    Unavailable {
        path: PathBuf,
        #[source]
        cause: std::io::Error,
    },
    #[error("the directory bindings file {0} is not valid; inspect or remove it")]
    Invalid(PathBuf),
    #[error(
        "the directory bindings file {0} was written by a newer logmastctl; upgrade to change it"
    )]
    Newer(PathBuf),
    #[error("{0} can be written by other users")]
    UnsafeDirectory(PathBuf),
}

pub fn default_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".logmast-config"))
        .join("logmast/bindings.json")
}

fn unavailable(path: &Path) -> impl FnOnce(std::io::Error) -> BindingError + '_ {
    move |cause| BindingError::Unavailable {
        path: path.to_path_buf(),
        cause,
    }
}

/// The bindings file, or none when it does not exist. A newer version is reported, so
/// reading can ignore it while writing refuses to replace it.
fn read(path: &Path) -> Result<Option<BindingFile>, BindingError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(unavailable(path)(error)),
    };
    let file: BindingFile =
        serde_json::from_str(&text).map_err(|_| BindingError::Invalid(path.to_path_buf()))?;
    if file.version > BINDINGS_VERSION {
        return Err(BindingError::Newer(path.to_path_buf()));
    }
    Ok(Some(file))
}

/// The binding for `directory` at `origin`: the one whose directory is the nearest ancestor.
pub fn resolve(
    path: &Path,
    origin: &str,
    directory: &Path,
) -> Result<Option<Binding>, BindingError> {
    let Some(file) = read(path)? else {
        return Ok(None);
    };
    let nearest: Option<Binding> = file
        .bindings
        .into_iter()
        .filter(|binding| binding.origin == origin && directory.starts_with(&binding.directory))
        .max_by_key(|binding| binding.directory.components().count());
    Ok(nearest)
}

/// Records or replaces the binding of one directory at one origin. A lock beside the file
/// keeps a person and an agent running `setup` at once from losing each other's binding.
pub fn bind(path: &Path, binding: Binding) -> Result<(), BindingError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| BindingError::Invalid(path.to_path_buf()))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(unavailable(parent))?;
    // A configuration directory may be a symlink (dotfiles); what it points at must be private.
    if fs::metadata(parent).map_err(unavailable(parent))?.mode() & 0o022 != 0 {
        return Err(BindingError::UnsafeDirectory(parent.to_path_buf()));
    }
    let lock_path = path.with_extension("lock");
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(unavailable(&lock_path))?;
    lock.lock().map_err(unavailable(&lock_path))?;
    let mut file = read(path)?.unwrap_or(BindingFile {
        version: BINDINGS_VERSION,
        bindings: Vec::new(),
    });
    file.bindings.retain(|existing| {
        !(existing.directory == binding.directory && existing.origin == binding.origin)
    });
    file.bindings.push(binding);
    // Replace atomically, so a crash never leaves a half-written file.
    let temporary = path.with_extension(format!("{}.tmp", Uuid::now_v7()));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(unavailable(&temporary))?;
    let bytes =
        serde_json::to_vec_pretty(&file).map_err(|_| BindingError::Invalid(path.to_path_buf()))?;
    output.write_all(&bytes).map_err(unavailable(&temporary))?;
    output.sync_all().map_err(unavailable(&temporary))?;
    fs::rename(&temporary, path).map_err(unavailable(path))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(unavailable(parent))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(directory: &str, workspace: Uuid) -> Binding {
        Binding {
            directory: PathBuf::from(directory),
            origin: "https://app.logmast.com".into(),
            workspace,
            project: None,
        }
    }

    #[test]
    fn the_nearest_bound_directory_wins_and_rebinding_replaces() -> Result<(), BindingError> {
        let root = std::env::temp_dir().join(format!("logmast-binding-{}", Uuid::now_v7()));
        let path = root.join("config/logmast/bindings.json");
        let (outer, inner, other) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        bind(&path, binding("/src", outer))?;
        bind(&path, binding("/src/ledger", inner))?;
        let origin = "https://app.logmast.com";
        let nearest = |directory: &str| {
            resolve(&path, origin, Path::new(directory))
                .map(|found| found.map(|binding| binding.workspace))
        };
        assert_eq!(nearest("/src/ledger/api")?, Some(inner));
        assert_eq!(nearest("/src/billing")?, Some(outer));
        assert_eq!(
            nearest("/srcx")?,
            None,
            "a sibling with a common text prefix is not inside"
        );
        assert_eq!(
            resolve(&path, "https://other.example", Path::new("/src/ledger"))?,
            None
        );
        bind(&path, binding("/src/ledger", other))?;
        assert_eq!(nearest("/src/ledger")?, Some(other));
        assert_eq!(read(&path)?.map(|file| file.bindings.len()), Some(2));
        let mode = fs::metadata(&path).map_err(unavailable(&path))?.mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(&root).map_err(unavailable(&root))?;
        Ok(())
    }

    #[test]
    fn a_newer_file_is_read_around_but_never_replaced() -> Result<(), BindingError> {
        let root = std::env::temp_dir().join(format!("logmast-binding-{}", Uuid::now_v7()));
        let path = root.join("logmast/bindings.json");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path.parent().unwrap_or(&root))
            .map_err(unavailable(&root))?;
        fs::write(&path, r#"{"version":2,"bindings":[],"future":true}"#)
            .map_err(unavailable(&path))?;
        assert!(matches!(
            resolve(&path, "https://app.logmast.com", Path::new("/src")),
            Err(BindingError::Newer(_))
        ));
        assert!(matches!(
            bind(&path, binding("/src", Uuid::now_v7())),
            Err(BindingError::Newer(_))
        ));
        fs::write(&path, r#"{"version":1,"bindings":[],"added_later":true}"#)
            .map_err(unavailable(&path))?;
        assert_eq!(
            resolve(&path, "https://app.logmast.com", Path::new("/src"))?,
            None,
            "unknown fields are ignored"
        );
        fs::remove_dir_all(&root).map_err(unavailable(&root))?;
        Ok(())
    }
}

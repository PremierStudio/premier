use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const FALLBACK_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Premier</title>
  <style>
    :root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #07090d; color: #d7dee8; }
    main { max-width: 36rem; padding: 2rem; border: 1px solid #243044; border-radius: 12px; background: #0d121a; }
    h1 { margin: 0 0 0.5rem; font-size: 1.25rem; }
    p { margin: 0.5rem 0; color: #8b97a8; line-height: 1.5; }
    code { display: block; margin-top: 0.75rem; padding: 0.75rem 0.9rem; border-radius: 8px; background: #111722; color: #c8d4e8; font-size: 0.85rem; white-space: pre-wrap; }
  </style>
</head>
<body>
  <main>
    <h1>Premier viewer assets missing</h1>
    <p>This binary was built without the web viewer bundle. Rebuild after building the viewer:</p>
    <code>npm install && npm run build
cargo install --path crates/premier-cli --force</code>
    <p>Or use the install script: <code style="display:inline;padding:0.15rem 0.35rem">./scripts/install.sh</code></p>
  </main>
</body>
</html>
"#;

fn main() -> io::Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let assets = manifest_dir.join("assets/viewer");
    let monorepo_dist = manifest_dir
        .join("../../apps/viewer/dist")
        .canonicalize()
        .unwrap_or_else(|_| manifest_dir.join("../../apps/viewer/dist"));

    println!("cargo:rerun-if-changed={}", monorepo_dist.display());
    println!("cargo:rerun-if-changed={}", assets.display());

    if monorepo_dist.join("index.html").is_file() {
        if assets.exists() {
            fs::remove_dir_all(&assets)?;
        }
        copy_dir(&monorepo_dist, &assets)?;
        println!(
            "cargo:warning=Premier embedding viewer from {}",
            monorepo_dist.display()
        );
    } else if !assets.join("index.html").is_file() {
        fs::create_dir_all(&assets)?;
        fs::write(assets.join("index.html"), FALLBACK_HTML)?;
        println!(
            "cargo:warning=Premier viewer dist not found at {}; embedding fallback HTML. Run `npm run build` then rebuild for the full viewer.",
            monorepo_dist.display()
        );
    }

    Ok(())
}

fn copy_dir(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let src = entry.path();
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&src, &dest)?;
        } else {
            fs::copy(&src, &dest)?;
        }
    }
    Ok(())
}

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import os, pathlib
print("=== haru-pack hello ===")
print("cwd (run-in-place)   :", os.getcwd())
print("__file__ (in stage)  :", pathlib.Path(__file__).resolve())
print("HARUPACK_EXE_DIR     :", os.environ.get("HARUPACK_EXE_DIR"))
cfg = pathlib.Path(os.environ["HARUPACK_EXE_DIR"]) / "config.toml"
print("adjacent config found:", cfg.exists())
if cfg.exists(): print("  config says:", cfg.read_text().strip())

"""Everything `haru-pack build` does, split by what it is FOR.

    orchestrate  the order the phases happen in — start here
    declare      what the project says about itself (pyproject / haru_pack.toml / CLI)
    validate     refusals for a declaration that cannot be honoured as written
    geo          the online location gate policy
    tree         copying the project in, and sizing what the launcher stages
    thick        what the --thick tier adds to a payload
    canary       the runtime knob catalogue and the cleartext stub-config section
    staging      where the launcher may stage, and where it may fetch its payload from
    inject       --env-append, and refusing an inject that would be silently dropped
    compiler     choosing a C compiler and running Nim
    assemble     building the payload tree the customer will actually run
    advisories   what a build TELLS the operator about the knobs they set
    emitkit      the --emit-c / --emit-nim reproduction kits
    receipt      the dict a build returns, and the promise that it is not a lie
    errors       BuildError, alone, so no sibling has to import another to raise

This file is a FACADE and must stay one. It re-exports the names that were importable from
the old single-file `build.py` so no caller had to change, and it deliberately holds no
logic of its own: it imports most of the package, which under INV-MODULARITY-03 makes it
"central", and a central module is only allowed to be thin. If you are about to add a
function here, it belongs in one of the modules above.
"""
from __future__ import annotations

# Re-exported for callers and for tests that reach through this module at the object they
# want to patch (`build.crypto.encrypt`, `build.toolchain.find_managed_zig`). These are the
# same module objects the submodules import, so patching one is seen everywhere.
from .. import crypto, toolchain
from .. import emit as emit_mod
from ..obfuscate import ObfuscationError
from .advisories import announce_staging, couple_staging_flags
from .assemble import assemble_payload
from .canary import (CANARY_KNOBS, DEFAULT_CANARY, _toml_basic_str, resolve_canary,
                     stub_config_bytes)
from .compiler import CC_ENV, CC_PROVIDERS, compile_launcher, resolve_cc
from .declare import DEFAULT_PYTHON, _declarations, _entry_relpath, _resolve
from .errors import BuildError
from .geo import DEFAULT_GEO_ENDPOINT, _normalize_geo, build_geo_policy
from .inject import _looks_secret_shaped, resolve_injects
from .orchestrate import build
from .staging import _is_root_like, resolve_base_path, resolve_source_url
from .tree import _staged_tree_bytes, copy_app_tree, target_is_host
from .validate import (CWD_POLICIES, prepare_output_dir, validate_encryption,
                       validate_manifest)
from .writable import resolve_writable

__all__ = [
    "BuildError", "build",
    "CANARY_KNOBS", "CC_ENV", "CC_PROVIDERS", "CWD_POLICIES", "DEFAULT_CANARY",
    "DEFAULT_GEO_ENDPOINT", "DEFAULT_PYTHON", "ObfuscationError",
    "announce_staging", "assemble_payload", "build_geo_policy", "compile_launcher",
    "couple_staging_flags", "crypto", "emit_mod", "resolve_base_path", "resolve_canary",
    "resolve_cc", "resolve_injects", "resolve_source_url", "resolve_writable", "stub_config_bytes",
    "copy_app_tree", "target_is_host", "toolchain", "prepare_output_dir",
    "validate_encryption", "validate_manifest",
    # Underscored, but imported by tests that check a refusal directly rather than through
    # a whole build. Kept exported so those tests keep naming the function they exercise.
    "_declarations", "_entry_relpath", "_is_root_like", "_looks_secret_shaped",
    "_normalize_geo", "_resolve", "_staged_tree_bytes", "_toml_basic_str",
]

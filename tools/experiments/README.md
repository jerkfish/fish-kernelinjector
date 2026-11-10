# Archived build/source experiments

These files are the experiments used to pin down the original compiler behaviour. They are
**not part of the delivered build**; `tools/build.bat` (source `src/main.cpp`) is canonical.

- `main_*.cpp` — source-form variants (raw pointer vs `unique_ptr`, `new CProcess()` vs
  `{}`, `operator=` vs `assign(ptr, len)`) built into the corresponding `build_*` directories.
- `build_*.bat` — one script per experiment, mirroring `tools/build.bat` with a different
  source/flags. `build_144.bat` selects MSVC 14.44 by presetting `VSTOOLS`; `msvc_env.bat`
  honours a caller-provided `VSTOOLS` and validates it.
- `cmp_test.cpp` — isolated `std::string == const char*` vs `strcmp(...) == 0` codegen test.

The conclusions are recorded in `NOTES/evidence.md` section 8. Build outputs (`build_*`)
are gitignored.

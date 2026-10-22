import sys
import subprocess
import shutil
import os

import glob

WINGET_DIR = r"C:\Users\Leandro\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe"
candidates = sorted(glob.glob(os.path.join(WINGET_DIR, "llvm-mingw-*", "bin", "clang.exe")))
if candidates:
    CLANG_PATH = candidates[-1]
else:
    CLANG_PATH = shutil.which("clang") or "clang.exe"

PROJECT_ROOT = r"D:\rust\certicheck"

import shlex

# 1. Lê e expande argumentos e response files ANTES de executar o clang
all_args = []
for arg in sys.argv[1:]:
    if arg.startswith("@") and os.path.isfile(arg[1:]):
        try:
            with open(arg[1:], "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                try:
                    tokens = shlex.split(content, posix=False)
                except Exception:
                    tokens = content.split()
                all_args.extend(tokens)
        except Exception:
            pass
    else:
        all_args.append(arg)

# 2. Executa o linker original
result = subprocess.run([CLANG_PATH] + sys.argv[1:])

# 3. Copia para a raiz APENAS se for o executável principal da aplicação
if result.returncode == 0:
    copied = False
    dest = os.path.join(PROJECT_ROOT, "certcheck-br.exe")

    for i, arg in enumerate(all_args):
        clean_arg = arg.strip('"').strip("'")
        out_file = None
        if clean_arg == "-o" and i + 1 < len(all_args):
            out_file = all_args[i + 1].strip('"').strip("'")
        elif clean_arg.startswith("-o") and len(clean_arg) > 2:
            out_file = clean_arg[2:].strip('"').strip("'").lstrip("=")

        if out_file:
            norm_parts = [p.lower() for p in os.path.normpath(out_file).split(os.sep)]
            base_name = os.path.basename(out_file).lower()
            if (
                "release" in norm_parts
                and (base_name == "certcheck-br.exe" or (base_name.startswith("certcheck_br") and base_name.endswith(".exe")))
                and os.path.isfile(out_file)
                and os.path.abspath(out_file).lower() != os.path.abspath(dest).lower()
            ):
                try:
                    shutil.copy2(out_file, dest)
                    copied = True
                except Exception as e:
                    print(f"[linker_wrapper] Failed to copy {out_file} to {dest}: {e}", file=sys.stderr)
                break

    # Fallback se rustc usou outro formato de argumento:
    if not copied:
        rel_candidate = os.path.join(PROJECT_ROOT, "target", "x86_64-pc-windows-gnullvm", "release", "certcheck-br.exe")
        if os.path.isfile(rel_candidate):
            try:
                shutil.copy2(rel_candidate, dest)
            except Exception:
                pass

sys.exit(result.returncode)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
password_validator.py

Política de contraseña:
- Longitud mínima: 10
- ≥ 3 mayúsculas [A-Z]
- ≥ 3 dígitos [0-9]
- ≥ 1 carácter especial en [#$%!@+=]
- Solo se permiten caracteres de [A-Za-z0-9#$%!@+=]

Entrada (por línea):
PASSWORD: <contraseña>s

Uso:
  python password_validator.py data_passwords.txt --summary 
"""
import sys, re, csv
from dataclasses import dataclass
from typing import List, Optional, Tuple

# Expresión regular global (coincidencia completa)
PASSWORD_REGEX_TEXT = (
    r'^(?=([A-Za-z0-9#$%!@+=]{10,})$)'  # longitud mínima y charset permitido
    r'(?=(?:.*[A-Z]){3})'               # ≥ 3 mayúsculas
    r'(?=(?:.*\d){3})'                  # ≥ 3 dígitos
    r'(?=.*[#$%!@+=]).*$'               # ≥ 1 especial del set
)
PASSWORD_REGEX = re.compile(PASSWORD_REGEX_TEXT)

@dataclass
class Result:
    line_no: int
    password: str
    valid: bool
    message: str

def parse_line(line: str) -> Optional[str]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if ":" in line:
        k, v = line.split(":", 1)
        return v.strip()
    return line  # tolerante: si no ponen "PASSWORD:", igual toma la cadena

def validate_password(pw: str) -> Tuple[bool, str]:
    if not isinstance(pw, str):
        return False, "Cadena inválida"

    # Chequeos con mensajes específicos
    if not re.fullmatch(r'[A-Za-z0-9#$%!@+=]{10,}', pw):
        if len(pw) < 10:
            return False, "Largo < 10 o caracteres fuera del conjunto permitido"
        return False, "Caracteres fuera del conjunto permitido"
    if len(re.findall(r'[A-Z]', pw)) < 3:
        return False, "Faltan mayúsculas (≥3)"
    if len(re.findall(r'\d', pw)) < 3:
        return False, "Faltan dígitos (≥3)"
    if not re.search(r'[#$%!@+=]', pw):
        return False, "Falta carácter especial [#$%!@+=]"

    # Validación global por consistencia
    ok = bool(PASSWORD_REGEX.fullmatch(pw))
    return (True, "OK") if ok else (False, "No cumple la política")

def load_and_validate(path: str) -> List[Result]:
    out: List[Result] = []
    with open(path, "r", encoding="utf-8") as f:
        for i, raw in enumerate(f, start=1):
            pw = parse_line(raw)
            if pw is None:
                continue
            valid, msg = validate_password(pw)
            out.append(Result(i, pw, valid, msg))
    return out

def print_table(results: List[Result]) -> None:
    from shutil import get_terminal_size
    width = get_terminal_size((120, 20)).columns
    print("-" * width)
    print(f"{'N°':>3} │ {'Password (abreviada)':<40} │ {'Válido':<6} │ Mensaje")
    print("-" * width)
    for r in results:
        shown = (r.password[:37] + "...") if len(r.password) > 40 else r.password
        print(f"{r.line_no:>3} │ {shown:<40} │ {('Sí' if r.valid else 'No'):^6} │ {r.message}")
    print("-" * width)

def print_summary(results: List[Result]) -> None:
    total = len(results)
    ok = sum(1 for r in results if r.valid)
    print("\nResumen:")
    print("--------")
    if total:
        pct = ok / total * 100.0
        print(f"Válidas: {ok}/{total} ({pct:.1f}%)")
    else:
        print("Sin casos")


def main(argv: List[str]) -> int:
    if not argv:
        print("Uso: python password_validator.py data_passwords.txt [--summary] ")
        return 2
    path = None
    summary = False
    export = None
    for arg in argv:
        if arg.startswith("--export="):
            export = arg.split("=", 1)[1]
        elif arg == "--summary":
            summary = True
        elif not path:
            path = arg
    if not path:
        print("Debe indicar ruta al .txt")
        return 2
    results = load_and_validate(path)
    print_table(results)
    if summary:
        print_summary(results)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════╗
║     IARS ENGINE — Identity Attack Path Simulator        ║
║     Red Team Graph Engine | kaleth4                     ║
╚══════════════════════════════════════════════════════════╝
"""

import json
import base64
import argparse
import time
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse

class C:
    RESET  = "\033[0m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    GRAY   = "\033[90m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════╗
║     🔴 IARS ENGINE — Identity Attack Path Simulator     ║
║     Red Team Graph Engine | kaleth4                     ║
╚══════════════════════════════════════════════════════════╝{C.RESET}
""")

def separador(titulo=""):
    if titulo:
        print(f"\n{C.GRAY}─── {C.BOLD}{titulo}{C.RESET}{C.GRAY} {'─' * (44 - len(titulo))}{C.RESET}")
    else:
        print(f"{C.GRAY}{'─' * 54}{C.RESET}")


# ─────────────────────────────────────────────────────
# MÓDULO 1: ANALIZADOR JWT
# ─────────────────────────────────────────────────────
class JWTAnalyzer:

    def _decode_b64(self, data):
        padding = 4 - len(data) % 4
        try:
            return json.loads(base64.urlsafe_b64decode(data + "=" * padding))
        except Exception:
            return {}

    def analyze(self, token):
        separador("ANALIZADOR JWT")
        partes = token.strip().split(".")
        if len(partes) != 3:
            print(f"  {C.RED}[✗] Token inválido{C.RESET}")
            return {}

        header  = self._decode_b64(partes[0])
        payload = self._decode_b64(partes[1])
        hallazgos = []

        print(f"  {C.CYAN}[*] Header : {json.dumps(header)}{C.RESET}")
        print(f"  {C.CYAN}[*] Payload: {json.dumps(payload)}{C.RESET}")

        alg = header.get("alg", "").lower()
        if alg == "none":
            hallazgos.append(("CRÍTICO", "alg=none — token aceptado sin firma"))
        elif alg in ["hs256", "hs384", "hs512"]:
            hallazgos.append(("MEDIO", f"{alg.upper()} simétrico — vulnerable si secreto es débil"))

        exp = payload.get("exp")
        if not exp:
            hallazgos.append(("ALTO", "Sin campo 'exp' — token no expira nunca"))
        else:
            ahora = datetime.now(timezone.utc).timestamp()
            vida = int((exp - ahora) / 3600)
            if vida > 720:
                hallazgos.append(("MEDIO", f"Vida útil excesiva: {vida}h ({vida//24} días)"))

        for campo in ["admin", "role", "is_admin", "superuser", "staff"]:
            if campo in json.dumps(payload).lower():
                hallazgos.append(("ALTO", f"Campo sensible en payload: '{campo}' — modificable si firma débil"))

        if not payload.get("state"):
            hallazgos.append(("MEDIO", "Sin parámetro 'state' — posible CSRF"))

        colores = {"CRÍTICO": C.RED, "ALTO": C.RED, "MEDIO": C.YELLOW, "INFO": C.CYAN}
        print()
        for nivel, desc in hallazgos:
            print(f"  {colores.get(nivel, C.GRAY)}[{nivel}]{C.RESET} {desc}")
        if not hallazgos:
            print(f"  {C.GREEN}[✓] Sin hallazgos críticos{C.RESET}")

        return {"header": header, "payload": payload, "hallazgos": hallazgos}


# ─────────────────────────────────────────────────────
# MÓDULO 2: SIMULADOR IAM CLOUD
# ─────────────────────────────────────────────────────
class CloudIAMSimulator:

    def __init__(self, roles, permisos):
        self.roles    = roles
        self.permisos = permisos

    def analizar(self):
        separador("SIMULADOR IAM CLOUD")
        rutas = []
        for rol, acciones in self.roles.items():
            recursos = set()
            for a in acciones:
                if a == "*":
                    recursos.add("TODOS_LOS_RECURSOS")
                else:
                    recursos.update(self.permisos.get(a, []))
            print(f"  {C.CYAN}[ROL] {rol}{C.RESET} → {list(recursos)}")
            if "*" in acciones:
                rutas.append((rol, "Wildcard '*' — acceso total sin restricción", "CRÍTICO"))
            elif len(recursos) > 3:
                rutas.append((rol, f"Acceso a {len(recursos)} recursos — sobre-privilegio", "MEDIO"))

        print()
        for rol, desc, nivel in rutas:
            color = C.RED if nivel == "CRÍTICO" else C.YELLOW
            print(f"  {color}[{nivel}]{C.RESET} {rol}: {desc}")
        return rutas

    def simular_escalacion(self, inicio, objetivo):
        separador("SIMULACIÓN DE ESCALACIÓN")
        a_inicio   = set(self.roles.get(inicio, []))
        a_objetivo = set(self.roles.get(objetivo, []))
        comunes    = a_inicio & a_objetivo

        print(f"  {C.CYAN}Inicio  : {inicio}{C.RESET}")
        print(f"  {C.CYAN}Objetivo: {objetivo}{C.RESET}")

        if "*" in a_inicio:
            print(f"  {C.RED}[!] {inicio} ya tiene acceso total — escalación trivial{C.RESET}")
        elif comunes:
            print(f"  {C.YELLOW}[!] Permisos compartidos: {comunes} — posible pivot{C.RESET}")
        else:
            print(f"  {C.GREEN}[✓] Sin permisos comunes directos{C.RESET}")


# ─────────────────────────────────────────────────────
# MÓDULO 3: MOTOR DE RUTAS (NÚCLEO)
# ─────────────────────────────────────────────────────
class AttackPathFinder:

    SEVERIDAD = {
        "Registro débil":           1,
        "Reutilización de token":   2,
        "IDOR":                     3,
        "RBAC Bypass":              3,
        "Escalación de privilegio": 4,
        "Rol sobreprivilegiado":    5,
        "JWT alg=none":             5,
        "OAuth redirect_uri":       4,
    }

    DESCRIPCIONES = {
        "Registro débil":           "Crear cuenta aprovechando validación débil en registro",
        "Reutilización de token":   "Reutilizar token de sesión sin rotación",
        "IDOR":                     "Abusar IDOR en endpoint de API",
        "RBAC Bypass":              "Bypassear control de acceso manipulando parámetros",
        "Escalación de privilegio": "Escalar privilegios mediante parámetro de rol modificable",
        "Rol sobreprivilegiado":    "Explotar rol con permisos excesivos",
        "JWT alg=none":             "Modificar JWT con alg=none para eliminar validación de firma",
        "OAuth redirect_uri":       "Abusar redirect_uri mal configurado para capturar token",
    }

    def __init__(self, nodos, aristas):
        self.nodos   = nodos
        self.aristas = aristas

    def _buscar(self, inicio, objetivo, ruta=None):
        if ruta is None:
            ruta = []
        ruta = ruta + [inicio]
        if inicio == objetivo:
            return [(ruta, [])]
        rutas = []
        for (src, dst, vuln) in self.aristas:
            if src == inicio and dst not in ruta:
                for (r, vs) in self._buscar(dst, objetivo, ruta):
                    rutas.append((r, [vuln] + vs))
        return rutas

    def score(self, vulns):
        return sum(self.SEVERIDAD.get(v, 1) for v in vulns)

    def analizar(self, inicio, objetivo):
        separador("MOTOR DE RUTAS DE ATAQUE")
        print(f"  {C.CYAN}Origen  : {inicio}{C.RESET}")
        print(f"  {C.CYAN}Objetivo: {objetivo}{C.RESET}\n")

        rutas = sorted(self._buscar(inicio, objetivo), key=lambda x: self.score(x[1]), reverse=True)

        if not rutas:
            print(f"  {C.GREEN}[✓] Sin rutas de ataque encontradas{C.RESET}")
            return []

        resultados = []
        for i, (ruta, vulns) in enumerate(rutas, 1):
            s = self.score(vulns)
            color = C.RED if s >= 10 else C.YELLOW if s >= 5 else C.CYAN
            print(f"  {color}[RUTA {i}] Score: {s}{C.RESET}")
            for j, nodo in enumerate(ruta):
                if j < len(ruta) - 1:
                    print(f"    {j+1}. {nodo}  {C.GRAY}→ [{vulns[j]}]{C.RESET}")
                else:
                    print(f"    {j+1}. {C.BOLD}{nodo}{C.RESET}  {C.RED}← OBJETIVO{C.RESET}")
            print()
            resultados.append({"ruta": ruta, "vulns": vulns, "score": s})
        return resultados

    def cadena_explotacion(self, ruta, vulns):
        separador("CADENA DE EXPLOTACIÓN")
        for i, vuln in enumerate(vulns):
            desc = self.DESCRIPCIONES.get(vuln, f"Explotar: {vuln}")
            print(f"  {C.BOLD}Paso {i+1}{C.RESET} → {desc}")
        impacto = "Acceso total al sistema" if self.score(vulns) >= 10 else "Escalación parcial de privilegios"
        print(f"\n  {C.RED}[IMPACTO]{C.RESET} {impacto}")


# ─────────────────────────────────────────────────────
# MÓDULO 4: OAUTH SIMULATOR
# ─────────────────────────────────────────────────────
class OAuthSimulator:

    def analizar(self, config):
        separador("SIMULADOR OAUTH")
        hallazgos = []
        redirect = config.get("redirect_uri", "")
        scope    = config.get("scope", "")
        pkce     = config.get("pkce", False)
        state    = config.get("state", None)

        print(f"  {C.CYAN}redirect_uri : {redirect}{C.RESET}")
        print(f"  {C.CYAN}scope        : {scope}{C.RESET}")
        print(f"  {C.CYAN}PKCE         : {pkce}{C.RESET}")
        print(f"  {C.CYAN}state        : {state}{C.RESET}\n")

        if "*" in redirect or redirect.endswith("/"):
            hallazgos.append(("CRÍTICO", "redirect_uri con wildcard — token capturable"))
        if redirect.startswith("http://"):
            hallazgos.append(("ALTO", "redirect_uri HTTP no cifrado"))
        if any(s in scope for s in ["admin", "write:*", "*", "full_access"]):
            hallazgos.append(("ALTO", f"Scope excesivo: '{scope}'"))
        if not pkce:
            hallazgos.append(("MEDIO", "PKCE ausente — vulnerable a code interception"))
        if not state:
            hallazgos.append(("MEDIO", "state ausente — vulnerable a CSRF OAuth"))

        colores = {"CRÍTICO": C.RED, "ALTO": C.RED, "MEDIO": C.YELLOW}
        for nivel, desc in hallazgos:
            print(f"  {colores.get(nivel, C.CYAN)}[{nivel}]{C.RESET} {desc}")
        if not hallazgos:
            print(f"  {C.GREEN}[✓] Configuración OAuth sin hallazgos{C.RESET}")
        return hallazgos


# ─────────────────────────────────────────────────────
# MÓDULO 5: RACE CONDITION ENGINE
# ─────────────────────────────────────────────────────
class RaceConditionEngine:

    def __init__(self, url, metodo="GET", headers=None, body=None):
        self.url        = url
        self.metodo     = metodo.upper()
        self.headers    = headers or {}
        self.body       = body or {}
        self.resultados = []

    def _request(self, idx):
        try:
            import urllib.request, urllib.parse
            data = urllib.parse.urlencode(self.body).encode() if self.body else None
            req  = urllib.request.Request(self.url, data=data, headers=self.headers, method=self.metodo)
            with urllib.request.urlopen(req, timeout=5) as r:
                self.resultados.append((idx, r.status, len(r.read())))
        except Exception as e:
            self.resultados.append((idx, "ERROR", str(e)))

    def ejecutar(self, n=10):
        separador("RACE CONDITION ENGINE")
        print(f"  {C.CYAN}URL     : {self.url}{C.RESET}")
        print(f"  {C.CYAN}Threads : {n}{C.RESET}\n")
        threads = [threading.Thread(target=self._request, args=(i,)) for i in range(n)]
        t0 = time.time()
        for t in threads: t.start()
        for t in threads: t.join()
        elapsed = round(time.time() - t0, 3)
        codigos = set(r[1] for r in self.resultados)
        print(f"  {C.CYAN}Tiempo : {elapsed}s{C.RESET}")
        if len(codigos) > 1:
            print(f"  {C.RED}[!] Respuestas inconsistentes: {codigos} — posible race condition{C.RESET}")
        else:
            print(f"  {C.GREEN}[✓] Respuestas consistentes: {codigos}{C.RESET}")
        return self.resultados


# ─────────────────────────────────────────────────────
# REPORTE JSON
# ─────────────────────────────────────────────────────
def exportar_reporte(datos, ruta="reporte_iars.json"):
    datos["fecha"] = datetime.now().isoformat()
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=2, ensure_ascii=False)
    print(f"\n  {C.CYAN}[*] Reporte exportado: {ruta}{C.RESET}")


# ─────────────────────────────────────────────────────
# DEMO
# ─────────────────────────────────────────────────────
def demo():
    separador("ESCENARIO DE DEMOSTRACIÓN")
    print(f"  {C.GRAY}Entorno: app web con API REST + Cloud IAM{C.RESET}\n")

    nodos = ["Usuario Anónimo","Cuenta de Usuario","Acceso API","Panel Admin","Almacenamiento Cloud"]
    aristas = [
        ("Usuario Anónimo",   "Cuenta de Usuario",   "Registro débil"),
        ("Cuenta de Usuario", "Acceso API",           "Reutilización de token"),
        ("Acceso API",        "Panel Admin",           "IDOR"),
        ("Acceso API",        "Panel Admin",           "RBAC Bypass"),
        ("Panel Admin",       "Almacenamiento Cloud", "Rol sobreprivilegiado"),
        ("Cuenta de Usuario", "Panel Admin",           "JWT alg=none"),
    ]

    engine = AttackPathFinder(nodos, aristas)
    rutas  = engine.analizar("Usuario Anónimo", "Almacenamiento Cloud")
    if rutas:
        engine.cadena_explotacion(rutas[0]["ruta"], rutas[0]["vulns"])

    jwt_test = (
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
        ".eyJzdWIiOiIxMjM0IiwiYWRtaW4iOnRydWUsImV4cCI6OTk5OTk5OTk5OX0"
        "."
    )
    jwt_res = JWTAnalyzer().analyze(jwt_test)

    roles    = {"usuario": ["leer_perfil"], "soporte": ["leer_perfil","leer_tickets"], "admin": ["*"]}
    permisos = {"leer_perfil": ["datos_usuario"], "leer_tickets": ["base_tickets"], "*": ["todos_los_recursos"]}
    iam = CloudIAMSimulator(roles, permisos)
    iam.analizar()
    iam.simular_escalacion("soporte", "admin")

    OAuthSimulator().analizar({
        "redirect_uri": "http://example.com/callback/",
        "scope": "read write:*",
        "pkce": False,
        "state": None
    })

    exportar_reporte({
        "rutas": [{"ruta": r["ruta"], "score": r["score"]} for r in rutas],
        "jwt_hallazgos": jwt_res.get("hallazgos", []),
    })


# ─────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="IARS Engine — Identity Attack Path Simulator")
    parser.add_argument("--demo",    action="store_true", help="Ejecutar demostración completa")
    parser.add_argument("--jwt",     metavar="TOKEN",     help="Analizar JWT específico")
    parser.add_argument("--reporte", metavar="ARCHIVO",   help="Exportar reporte JSON")
    args = parser.parse_args()

    if args.jwt:
        res = JWTAnalyzer().analyze(args.jwt)
        if args.reporte:
            exportar_reporte({"jwt": res}, args.reporte)
        return

    demo()


if __name__ == "__main__":
    main()
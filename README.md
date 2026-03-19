<div align="center">

```
██╗ █████╗ ██████╗ ███████╗    ███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗
██║██╔══██╗██╔══██╗██╔════╝    ██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝
██║███████║██████╔╝███████╗    █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗  
██║██╔══██║██╔══██╗╚════██║    ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝  
██║██║  ██║██║  ██║███████║    ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗
╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝
         I D E N T I T Y   A T T A C K   P A T H   S I M U L A T O R
```

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python&logoColor=white)
![Category](https://img.shields.io/badge/Category-Red%20Team%20%7C%20IAM-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Docker-orange?style=for-the-badge&logo=linux)
![Graph](https://img.shields.io/badge/Engine-Graph%20Traversal-purple?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-En%20desarrollo-yellow?style=for-the-badge)

> **Framework de simulación de rutas de ataque basadas en identidad.**  
> No busca vulnerabilidades aisladas — responde: **¿cómo me convierto en admin?**

</div>

---

## 🎯 ¿Qué resuelve IARS Engine?

Las herramientas tradicionales encuentran CVEs.  
Este framework **modela entornos completos** y descubre cadenas de explotación:

```
Entrada → Pivote → Escalación → Objetivo
   │          │          │          │
Registro   Token      IDOR       Admin
débil      reuse    horizontal   Panel
```

**Responde preguntas reales de Red Team:**
- ¿Existe un camino desde usuario anónimo hasta admin?
- ¿Qué combinación de fallas lo hace posible?
- ¿Cuál es el impacto real de la cadena?

---

## 🧩 Arquitectura del Motor

```
┌─────────────────────────────────────────────────────┐
│                   IARS ENGINE                       │
│                                                     │
│  ┌──────────┐   ┌──────────┐   ┌────────────────┐  │
│  │  Token   │   │  IDOR +  │   │  Cloud IAM     │  │
│  │ Analyzer │   │  AuthZ   │   │  Simulator     │  │
│  └────┬─────┘   └────┬─────┘   └──────┬─────────┘  │
│       │              │                │             │
│       └──────────────▼────────────────┘             │
│                      │                              │
│            ┌─────────▼──────────┐                  │
│            │  Attack Path Finder │                  │
│            │  (Graph Traversal) │                  │
│            └─────────┬──────────┘                  │
│                      │                              │
│            ┌─────────▼──────────┐                  │
│            │  Exploit Chain      │                  │
│            │  Report Generator  │                  │
│            └────────────────────┘                  │
└─────────────────────────────────────────────────────┘
```

---

## ⚙️ Módulos

### 🔐 1. Analizador de Tokens y Sesiones

Parsea y testea JWT y cookies de sesión en busca de fallas comunes:

```python
import jwt

def analyze_jwt(token):
    decoded = jwt.decode(token, options={"verify_signature": False})
    print("[+] JWT Payload:", decoded)

    if "admin" in str(decoded).lower():
        print("[!] Indicador de privilegio dentro del token")
```

**Detecta:**

| Falla | Descripción |
|-------|-------------|
| `alg: none` | Firma deshabilitada — token aceptado sin verificación |
| `HS/RS confusion` | Confusión de algoritmo — bypass de firma |
| Expiración débil | Tokens con vida útil excesiva |
| Flags faltantes | Cookies sin `HttpOnly` o `Secure` |
| Predictibilidad | Session IDs secuenciales o débiles |

---

### 🔁 2. Motor de Grafos IDOR + Autorización

No solo testea IDs — **mapea relaciones entre recursos**:

```python
nodos = [
    "Usuario Anónimo",
    "Cuenta de Usuario",
    "Acceso API",
    "Panel Admin",
    "Almacenamiento Cloud"
]

aristas = [
    ("Usuario Anónimo", "Cuenta de Usuario",  "Registro débil"),
    ("Cuenta de Usuario", "Acceso API",        "Reutilización de token"),
    ("Acceso API",        "Panel Admin",        "IDOR"),
    ("Panel Admin",       "Almacenamiento Cloud","Rol sobreprivilegiado")
]
```

- Detección de escalación **horizontal** (acceder a recursos de otro usuario)
- Detección de escalación **vertical** (acceder a funciones de rol superior)

---

### ☁️ 3. Simulador de Mala Configuración Cloud IAM

Simula entornos IAM tipo AWS/GCP/Azure sin necesitar credenciales reales:

```python
roles = {
    "usuario":  ["leer_perfil"],
    "soporte":  ["leer_perfil", "leer_tickets"],
    "admin":    ["*"]
}

permisos = {
    "leer_perfil":  ["datos_usuario"],
    "leer_tickets": ["base_tickets"],
    "*":            ["todos_los_recursos"]
}
```

**Detecta:**
- Roles con permisos excesivos (`*` sin restricción)
- Rutas de escalación vía asunción de roles
- Políticas que permiten movimiento lateral

---

### 🧠 4. Buscador de Rutas de Ataque *(núcleo del sistema)*

Traversal de grafos para encontrar todos los caminos posibles hacia el objetivo:

```python
def encontrar_rutas(grafo, inicio, objetivo, ruta=[]):
    ruta = ruta + [inicio]

    if inicio == objetivo:
        return [ruta]

    rutas = []
    for (src, dst, vuln) in grafo:
        if src == inicio and dst not in ruta:
            nuevas = encontrar_rutas(grafo, dst, objetivo, ruta)
            for r in nuevas:
                rutas.append((r, vuln))
    return rutas
```

---

### 🎭 5. Generador de Cadenas de Explotación

Output estructurado de cada ruta encontrada:

```
[RUTA DE ATAQUE ENCONTRADA]

Paso 1 → Registrar cuenta con lógica débil
Paso 2 → Abusar IDOR en /api/user?id=124
Paso 3 → Extraer token de administrador
Paso 4 → Acceder a panel /admin
Paso 5 → Exfiltrar datos sensibles del storage

Impacto: Toma total de cuenta + filtración de datos
Score:   CRÍTICO (CVSS estimado: 9.1)
```

---

## 🚀 Características Avanzadas

| Módulo | Descripción |
|--------|-------------|
| 🧬 **OAuth Abuse Simulator** | `redirect_uri` mal configurado, fuga de tokens, account linking |
| 🧪 **Race Condition Engine** | Requests paralelos — doble gasto, duplicación de privilegios |
| 🕵️ **Blind Attack Detection** | SQLi basado en tiempo, lógica booleana ciega |
| 🧱 **WAF Evasion Layer** | Mutación de payloads, encoding, randomización de case |
| 📊 **Visual Graph Export** | Exporta a Neo4j / Graphviz para visualización del árbol de ataque |

**Ejemplo de grafo exportado:**

```
Usuario → IDOR → Admin → S3 Bucket → Exfiltración de datos
```

---

## 📦 Instalación

```bash
# Clonar repositorio
git clone https://github.com/kaleth4/iars-engine.git
cd iars-engine

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar contra lab local (Docker recomendado)
python3 iars.py --target http://localhost:8080 --mode full
```

---

## 🧪 Entornos de prueba recomendados

```
✔ DVWA (Damn Vulnerable Web App)
✔ Juice Shop (OWASP)
✔ HackTheBox / TryHackMe
✔ Lab propio en Docker
✘ NUNCA en sistemas sin autorización explícita
```

---

## 📈 Roadmap

- [x] Motor de grafos de ataque con traversal
- [x] Analizador de JWT y sesiones
- [x] Simulador IAM Cloud
- [x] Generador de cadenas de explotación
- [ ] Exportación visual a **Neo4j / Graphviz**
- [ ] **OAuth Abuse Simulator** completo
- [ ] **Race Condition Engine**
- [ ] Reporte exportable en **PDF / HTML**
- [ ] Integración con **Shodan API**

---

## 🔥 ¿Por qué este proyecto es diferente?

> La mayoría de candidatos **ejecutan herramientas**.  
> Pocos **modelan entornos y descubren rutas**.

```
❌ Hunter de bug bounty → encuentra vulnerabilidades
✅ Operador Red Team   → modela sistemas, descubre cadenas, explica impacto
```

**En entrevista:**
> *"Este framework modela entornos de identidad como grafos dirigidos y aplica traversal para descubrir cadenas de explotación completas, desde acceso anónimo hasta privilegio máximo, priorizando rutas por impacto."*

---

## ⚠️ Disclaimer

> Herramienta desarrollada con fines educativos y de investigación en seguridad.  
> Úsala únicamente en entornos propios o con autorización explícita por escrito.  
> El autor no se responsabiliza por uso indebido.

---

<div align="center">

**Kaled Corcho** — [github.com/kaleth4](https://github.com/kaleth4)  
`Cybersecurity Analyst Jr.` · `Red Team` · `Identity Security`

</div>

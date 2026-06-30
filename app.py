"""
Frontend de consultas - Proyecto Base de Datos I (Restaurante "Central")
=========================================================================

Pequeno servidor Flask que expone una caja de SQL libre para probar consultas
contra la base `central` en PostgreSQL local.

Seguridad anti-SQL-injection (defensa en capas):
  1. Solo se aceptan sentencias de LECTURA: SELECT / WITH / EXPLAIN / TABLE /
     VALUES / SHOW. Cualquier otra cosa se rechaza antes de tocar la BD.
  2. Una sola sentencia por ejecucion: se prohibe encadenar con ';'
     (evita el clasico  "... ; DROP TABLE ...").
  3. Lista negra de funciones peligrosas (lectura de archivos, COPY, pg_sleep,
     dblink, etc.) que un superusuario podria abusar.
  4. CAPA REAL DE DEFENSA: cada consulta corre en una conexion marcada
     `default_transaction_read_only = on` con `statement_timeout`. Aunque algo
     se colara por las capas anteriores, PostgreSQL rechaza TODA escritura y
     mata las consultas que tardan demasiado.
  5. Se limita el numero de filas devueltas al navegador.

Ejecutar:
    pip install -r requirements.txt
    python app.py
    -> abrir http://127.0.0.1:5000
"""

import json
import os
import re
import time

import psycopg2
from flask import Flask, jsonify, render_template, request

# --------------------------------------------------------------------------
# Configuracion de conexion (override por variables de entorno si se quiere)
# IMPORTANTE: host 127.0.0.1 -> pg_hba.conf usa 'trust' para esa IP, no pide
# password. Por ::1 (IPv6) usaria scram-sha-256 y se colgaria pidiendo clave.
# --------------------------------------------------------------------------
DB_CONFIG = {
    "host": os.environ.get("PGHOST", "127.0.0.1"),
    "port": os.environ.get("PGPORT", "5432"),
    "dbname": os.environ.get("PGDATABASE", "central"),
    "user": os.environ.get("PGUSER", "postgres"),
    "password": os.environ.get("PGPASSWORD", ""),  # vacio = trust
}

MAX_ROWS = 1000          # filas maximas que se envian al navegador
STATEMENT_TIMEOUT_MS = 15000  # 15s: corta consultas demasiado pesadas

app = Flask(__name__)


# --------------------------------------------------------------------------
# Validacion / guardia anti-inyeccion
# --------------------------------------------------------------------------

# Verbos con los que puede empezar una sentencia de SOLO LECTURA.
ALLOWED_STARTS = ("select", "with", "explain", "table", "values", "show")

# Funciones / comandos peligrosos aunque aparezcan dentro de un SELECT.
# El usuario 'postgres' es superusuario, asi que bloquearlos importa.
DANGER_TOKENS = (
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
    "lo_import", "lo_export", "copy", "dblink", "pg_sleep",
    "pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf",
)


def strip_sql_comments(sql: str) -> str:
    """Quita comentarios -- y /* */ para que la validacion no se enganhe."""
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    sql = re.sub(r"--[^\n]*", " ", sql)
    return sql


def validate_sql(raw: str):
    """Devuelve (sql_limpio, None) si es valida, o (None, mensaje_error)."""
    if not raw or not raw.strip():
        return None, "La consulta esta vacia."

    cleaned = strip_sql_comments(raw).strip()
    if not cleaned:
        return None, "La consulta solo contiene comentarios."

    # Quitar un unico ';' final (se permite por comodidad).
    cleaned = cleaned.rstrip().rstrip(";").rstrip()

    # 1) Una sola sentencia: ya no debe quedar ningun ';'.
    if ";" in cleaned:
        return None, ("Solo se permite UNA sentencia. Quita los ';' intermedios "
                      "(no se pueden encadenar consultas).")

    # 2) Debe empezar con un verbo de lectura.
    first_word = re.match(r"\s*([a-zA-Z]+)", cleaned)
    if not first_word or first_word.group(1).lower() not in ALLOWED_STARTS:
        return None, ("Solo se permiten consultas de LECTURA "
                      "(SELECT, WITH, EXPLAIN, TABLE, VALUES, SHOW). "
                      "Esta herramienta es de solo lectura.")

    # 2b) EXPLAIN no puede traer ANALYZE sobre algo que escriba; el modo
    #     READ ONLY ya lo bloquea, pero damos un mensaje claro igual.

    # 3) Lista negra de tokens peligrosos (como palabra completa).
    lowered = cleaned.lower()
    for tok in DANGER_TOKENS:
        if re.search(r"\b" + re.escape(tok) + r"\b", lowered):
            return None, f"Funcion no permitida: '{tok}'."

    return cleaned, None


# --------------------------------------------------------------------------
# Acceso a la base de datos (conexion read-only por peticion)
# --------------------------------------------------------------------------

def get_readonly_connection():
    """Conexion nueva forzada a SOLO LECTURA con timeout de sentencia.

    Las opciones se aplican como defaults de sesion, asi que TODA transaccion
    en esta conexion es read-only: PostgreSQL rechaza INSERT/UPDATE/DELETE/DDL.
    """
    options = (
        f"-c default_transaction_read_only=on "
        f"-c statement_timeout={STATEMENT_TIMEOUT_MS} "
        f"-c idle_in_transaction_session_timeout={STATEMENT_TIMEOUT_MS}"
    )
    return psycopg2.connect(options=options, connect_timeout=5, **DB_CONFIG)


def run_query(sql: str):
    """Ejecuta la consulta validada y devuelve un dict para el frontend."""
    conn = None
    try:
        conn = get_readonly_connection()
        with conn.cursor() as cur:
            start = time.perf_counter()
            cur.execute(sql)
            elapsed_ms = (time.perf_counter() - start) * 1000

            if cur.description is None:
                # No deberia pasar con lecturas, pero por si acaso.
                return {"columns": [], "rows": [], "rowcount": 0,
                        "truncated": False, "elapsed_ms": round(elapsed_ms, 1)}

            columns = [d.name for d in cur.description]
            rows = cur.fetchmany(MAX_ROWS + 1)
            truncated = len(rows) > MAX_ROWS
            rows = rows[:MAX_ROWS]

            # Convertir todo a str-friendly (Decimal, date, None -> JSON ok).
            data = [[(None if v is None else _as_cell(v)) for v in row]
                    for row in rows]

        conn.rollback()  # nada que confirmar; cerramos limpio
        return {
            "columns": columns,
            "rows": data,
            "rowcount": len(data),
            "truncated": truncated,
            "elapsed_ms": round(elapsed_ms, 1),
        }
    except psycopg2.Error as e:
        # Mensaje de PostgreSQL (incluye el "read-only transaction" si aplica).
        msg = (e.diag.message_primary if e.diag and e.diag.message_primary
               else str(e)).strip()
        return {"error": msg}
    finally:
        if conn is not None:
            conn.close()


def _as_cell(value):
    """Normaliza un valor para JSON manteniendo numeros nativos."""
    if isinstance(value, (int, float, bool)):
        return value
    return str(value)


# --------------------------------------------------------------------------
# Rutas
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Metadatos para el panel lateral (esquema resumido + consultas de ejemplo)
# --------------------------------------------------------------------------
SCHEMA = {
    "cliente": ["id_cliente", "dni", "nombre", "apellido", "telefono", "email",
                "fecha_registro"],
    "restriccion_alimentaria": ["id_cliente", "tipo", "descripcion"],
    "turno": ["id_turno", "fecha", "tipo", "hora_inicio", "hora_fin"],
    "mesa": ["id_mesa", "numero", "capacidad", "zona", "estado"],
    "experiencia": ["id_experiencia", "nombre", "descripcion", "precio_persona",
                    "cantidad_momentos", "vigente"],
    "momento": ["id_experiencia", "num_orden", "nombre", "descripcion"],
    "maridaje": ["id_maridaje", "nombre", "tipo", "precio_persona", "con_alcohol"],
    "bebida": ["id_bebida", "nombre", "tipo", "precio", "incluida_en_experiencia",
               "con_alcohol", "disponible"],
    "reserva": ["id_reserva", "fecha", "hora", "num_comensales", "num_maridajes",
                "estado", "prepago", "id_cliente", "id_mesa", "id_turno",
                "id_experiencia", "id_maridaje"],
    "empleado": ["id_empleado", "dni", "nombre", "apellido", "fecha_contratacion",
                 "telefono", "tipo_empleado"],
    "mesero": ["id_empleado", "propinas_acumuladas"],
    "chef": ["id_empleado", "especialidad"],
    "host": ["id_empleado", "idiomas"],
    "cajero": ["id_empleado", "caja_asignada"],
    "administrador": ["id_empleado", "nivel_acceso"],
    "asignacion_turno": ["id_empleado", "id_turno", "hora_ingreso", "hora_salida"],
    "pedido": ["id_pedido", "fecha_hora_apertura", "fecha_hora_cierre", "estado",
               "id_mesa", "id_turno", "id_experiencia", "id_maridaje", "id_empleado"],
    "detalle_pedido": ["id_pedido", "num_linea", "hora_servicio", "estado",
                       "id_experiencia", "num_orden"],
    "detalle_bebida": ["id_pedido", "num_linea", "cantidad", "precio_unitario",
                       "hora_servicio", "estado", "id_bebida"],
    "factura": ["id_factura", "fecha_emision", "subtotal_experiencia",
                "subtotal_maridaje", "subtotal_bebidas_carta", "subtotal", "igv",
                "total", "estado", "id_pedido", "id_empleado"],
    "pago": ["id_factura", "num_pago", "monto", "medio_pago", "fecha_pago",
             "referencia"],
}

@app.route("/")
def index():
    return render_template(
        "index.html",
        schema_json=json.dumps(SCHEMA),
    )


@app.route("/api/query", methods=["POST"])
def api_query():
    payload = request.get_json(silent=True) or {}
    raw_sql = payload.get("sql", "")

    sql, error = validate_sql(raw_sql)
    if error:
        return jsonify({"error": error}), 400

    result = run_query(sql)
    status = 400 if "error" in result else 200
    return jsonify(result), status


@app.route("/api/health")
def health():
    """Comprueba que la BD responde (util para diagnosticar conexion)."""
    try:
        conn = get_readonly_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT current_database(), version()")
            db, ver = cur.fetchone()
        conn.close()
        return jsonify({"ok": True, "database": db, "version": ver})
    except psycopg2.Error as e:
        return jsonify({"ok": False, "error": str(e).strip()}), 500


if __name__ == "__main__":
    print("=" * 60)
    print(" Frontend Consultas - BD Central")
    print(f"   Conectando a: {DB_CONFIG['user']}@{DB_CONFIG['host']}:"
          f"{DB_CONFIG['port']}/{DB_CONFIG['dbname']}")
    print("   Abrir: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)

# Frontend de consultas — BD Central

Consola web de **solo lectura** para probar consultas SQL contra la base
`central` (PostgreSQL local) del proyecto de Base de Datos I.

## Cómo correrlo

```bash
cd C:\Users\Adrian\Desktop\BaseDatos\webapp
pip install -r requirements.txt
python app.py
```

Luego abrir <http://127.0.0.1:5000>.

## Conexión

Por defecto se conecta a `postgres@127.0.0.1:5432/central` **sin contraseña**
(porque `pg_hba.conf` usa `trust` para `127.0.0.1`). Se puede cambiar con
variables de entorno antes de arrancar:

```
PGHOST  PGPORT  PGDATABASE  PGUSER  PGPASSWORD
```

## Cómo se previene la inyección SQL

La caja acepta SQL libre, así que la protección es en **capas** (ver `app.py`):

1. **Solo lectura por verbo:** únicamente `SELECT / WITH / EXPLAIN / TABLE /
   VALUES / SHOW`. Cualquier otra cosa se rechaza antes de tocar la BD.
2. **Una sola sentencia:** se prohíbe encadenar con `;`
   (bloquea `... ; DROP TABLE ...`).
3. **Lista negra** de funciones peligrosas (`pg_read_file`, `copy`, `pg_sleep`,
   `dblink`, …).
4. **Capa real de defensa** — cada consulta corre en una conexión
   `default_transaction_read_only = on` con `statement_timeout`. Aunque algo se
   colara, PostgreSQL **rechaza toda escritura** y corta consultas eternas.
5. **Límite de filas** devueltas al navegador (1000).

Prueba el ejemplo *"Prueba anti-inyección"* del panel: será rechazado.

> Nota: esta herramienta NO usa consultas parametrizadas porque el usuario
> escribe la consulta completa a propósito. En una app real, los datos del
> usuario van **siempre** como parámetros (`%s`) y nunca concatenados.

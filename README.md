# Sistema pruebas de consistencia LAB (ISO 5725-2)

Aplicación web desarrollada en Django 5.2  para el cálculo estadístico interlaboratorio (Mandel h y k, Cochran y Grubbs), gestión de muestras/métodos en PostgreSQL, exportación de reportes en Excel y PDF.

## Características principales

* **Cálculos estadísticos ISO 5725-2:** Evaluación de consistencia  mediante pruebas de Mandel (h y k), Cochran y Grubbs, con generación de gráficas y reportes en `.xlsx` y `.pdf`.

* **Autenticación y sesiones:** Rutas de acceso (`/login`). 

## Estructura del proyecto


```text
PythonProject10/
├── static/                 # Archivos estáticos (logo.png, logo2.png)
├── staticfiles/            # Estáticos recolectados para DEBUG=False / producción
├── templates/
│   ├── login.html          # Vista de inicio de sesión
│   ├── vista1.html          # Consola principal de cálculos
│   └── registros.html      # Historial y consulta de registros
├── .env                    # Variables de entorno y credenciales 
├── main.py                 # Codigo principal vistas, calculos, seguridad, bases de datos.
├── requirements.txt        # Dependencias 
└── security_audit.log      # Loggs de estado
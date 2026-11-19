<div align="center">
  <img src="logo.png" alt="DRIVE-SEC Logo" width="420"/>

  # DRIVE-SEC v2.3
  **Suite de Diagnóstico de Hardware, Adquisición Forense Digital y Auditoría de Particiones para Linux**

  ![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
  ![Platform](https://img.shields.io/badge/OS-Linux%20(Debian%2FUbuntu%2FKali)-success?style=for-the-badge&logo=linux&logoColor=white)
  ![License](https://img.shields.io/badge/Focus-Blue%20Team%20%26%20DFIR-darkred?style=for-the-badge)
</div>

---

## 🛡️ Descripción General

**DRIVE-SEC** es una herramienta de interfaz gráfica construida en Python (`CustomTkinter`) diseñada para administradores de sistemas, técnicos de soporte crítico y analistas de **Forense Digital y Respuesta a Incidentes (DFIR)**. 

**controlar lo que ocurre en la capa física y lógica del almacenamiento sin depender de abstracciones opacas**, esta suite permite evaluar la salud real de unidades de almacenamiento, detectar hardware fraudulento, clonar evidencia bit a bit manteniendo la cadena de custodia y revelar particiones ocultas al sistema operativo.

---

## ⚡ Capacidades y Módulos Principales

1. **Salud S.M.A.R.T. (`smartctl`):** Consulta telemetría interna de discos HDD, SSD y NVMe (incluso a través de puentes USB-SATA mediante `-d sat`), alertando sobre sectores reasignados, pendientes, errores CRC y desgaste de celdas.
2. **Benchmark de Lectura por Zonas (`dd`):** Evalúa la velocidad secuencial directa (`iflag=direct`) en tres puntos críticos del medio (inicio, medio y final) para detectar degradación física.
3. **Benchmark de Escritura:** Mide el rendimiento real de escritura secuencial mediante archivos temporales sanitizados automáticamente al finalizar.
4. **Escaneo de Superficie (`badblocks`):** Inspección no destructiva en modo **solo lectura** de bloques físicos de 4096 bytes con cálculo de tiempo estimado (ETA) y cancelación segura.
5. **Detección Anti-Fraude de Capacidad (`f3probe`):** Identifica memorias USB o tarjetas SD falsificadas cuyo controlador reporta capacidades infladas.
6. **Adquisición Forense RAW (`.dd`):** Clonado *bitstream* bit a bit con cálculo simultáneo de hashes **MD5** y **SHA-256** al vuelo en una sola pasada de lectura, generando un archivo `.log` de cadena de custodia automático.
7. **Integración con Autopsy:** Copia el hash SHA-256 de verificación al portapapeles y lanza **Autopsy** listo para ingerir la imagen adquirida.
8. **Particionado y Aprovisionamiento (`parted` / `wipefs`):** Limpia firmas previas, reconstruye tablas de particiones **GPT** desde cero y formatea volúmenes en `ext4` (con ajuste automático de permisos de usuario), `exFAT`, `FAT32` o `NTFS`.
9. **Auditoría de Particiones Ocultas y Montaje Forense (`RO`):** Inspecciona la tabla cruda a nivel de bytes para revelar particiones con flags `hidden`, `esp`, `msftres`, `diag` o espacios no asignados (*unallocated gaps*), permitiendo montarlas en modo **estricto solo lectura (`ro,noload`)** sin alterar metadatos ni reproducir el *journal*.

---

## 🔒 Arquitectura de Seguridad

* **Sin inyección de comandos:** Nunca se utiliza `shell=True`; todas las llamadas al sistema se ejecutan mediante listas estrictas de argumentos (`subprocess.Popen`).
* **Prevención de errores humanos:** Solo es posible seleccionar dispositivos detectados dinámicamente por `lsblk`; no existe entrada manual de rutas de bloque (`/dev/sdX`).
* **Protección del sistema anfitrión:** Cualquier unidad que contenga puntos de montaje críticos (`/`, `/boot`, `/home`, `[SWAP]`) bloquea automáticamente las operaciones destructivas o de escritura.
* **Elevación granular de privilegios:** Utiliza `pkexec` (PolicyKit) únicamente en los subprocesos que requieren acceso crudo a dispositivos de bloque, manteniendo la interfaz gráfica en espacio de usuario.

---

## 📋 Requisitos del Sistema

### 1. Dependencias del Sistema Operativo (Debian / Ubuntu / Kali Linux / Linux Mint)

Actualiza tus repositorios e instala las utilidades base y forenses:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-tk smartmontools e2fsprogs util-linux policykit-1 udisks2 parted dosfstools exfatprogs ntfs-3g
```

#### Herramientas Opcionales (Recomendadas para funcionalidad completa):
```bash
# Para detección de memorias USB falsificadas (Módulo 5)
sudo apt install -y f3

# Para análisis forense digital post-adquisición (Módulo 7)
sudo apt install -y autopsy
```

### 2. Dependencias de Python

Se recomienda utilizar un entorno virtual (`venv`) o instalar las librerías gráficas necesarias:

```bash
pip install customtkinter pillow
```

---

## 🚀 Instalación y Ejecución

1. **Clona el repositorio:**
   ```bash
   git clone https://github.com/MRVYP3R/driver-sec
   cd drive-sec
   ```

2. **Verifica la estructura de archivos:**
   Asegúrate de que el archivo de imagen `logo.png` se encuentre en el mismo directorio que el script principal (`driverSecClaude.py`) para que la suite cargue tanto el banner superior como el icono de ventana:
   ```text
   drive-sec/
   ├── driver-sec.py
   ├── logo.png
   └── README.md
   ```

3. **Asigna permisos de ejecución y arranca la suite:**
   ```bash
   chmod +x driver-sec.py
   python3 driver-sec.py
   ```
   > **Nota:** Ejecuta el programa como tu usuario normal (no uses `sudo python3 ...`). Cuando una prueba o adquisición requiera acceso de bajo nivel al hardware, **DRIVE-SEC** solicitará tu contraseña de forma gráfica mediante `pkexec`.

---

## 🧭 Guía Rápida de Uso Operativo

### Escenario A: Auditoría de Particiones Ocultas
1. Conecta la unidad externa (o marca **`Mostrar todos los discos`** para auditar unidades internas).
2. Haz clic en **`9 · Ver Particiones (Ocultas)`**.
3. Revisa el mapa de sectores: las particiones sin punto de montaje o con flags ocultos aparecerán marcadas en amarillo junto con cualquier hueco de espacio no asignado.
4. Para inspeccionar el contenido de una partición oculta sin dejar rastros de escritura, selecciónala en el desplegable inferior del diálogo y pulsa **`🔍 Montar RO y Abrir`**. Al cerrar esa ventana, la unidad se desmontará automáticamente.

### Escenario B: Adquisición Forense hacia Autopsy
1. Desmonta las particiones activas del disco sospechoso pulsando **`⏏ Desmontar`** (garantiza que el sistema operativo no escriba en el medio durante la copia).
2. Pulsa **`6 · Clonar Imagen (.dd)`** y selecciona una ruta de destino en un disco distinto con espacio suficiente.
3. Al finalizar, verifica los hashes **MD5 / SHA-256** generados en el archivo `.log` adjunto.
4. Pulsa **`7 · Analizar en Autopsy`** para lanzar la suite forense con el hash SHA-256 ya copiado en tu portapapeles.

---

## ⚠️ Aviso Legal y Ético

Esta herramienta ha sido desarrollada con fines educativos, de administración de sistemas, diagnóstico de hardware y análisis forense digital autorizado. El autor no se hace responsable por la pérdida de datos derivada del uso incorrecto de las funciones de particionado y formateo (`Módulo 8`). Verifica siempre la ruta del dispositivo (`/dev/sdX` o `/dev/nvmeXnY`) antes de ejecutar operaciones destructivas.
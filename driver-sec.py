#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DRIVE-SEC v2.3 // Diagnóstico, Adquisición Forense, Auditoría de Particiones y Aprovisionamiento

Dependencias:
    pip install customtkinter
    sudo apt install python3-tk smartmontools e2fsprogs policykit-1 udisks2 parted dosfstools exfatprogs ntfs-3g
    sudo apt install f3        # opcional: detecta memorias USB falsificadas
    sudo apt install autopsy   # opcional: análisis forense digital

Herramientas:
    1. S.M.A.R.T.              salud, sectores reasignados/pendientes, desgaste NVMe, temperatura
    2. Lectura                 velocidad en 3 zonas del disco (inicio / medio / final)
    3. Escritura               archivo temporal en la partición montada (se borra al terminar)
    4. Superficie              badblocks en modo lectura, con progreso, ETA y cancelación
    5. Capacidad real          f3probe: detecta pendrives con capacidad inflada
    6. Imagen Forense (.dd)    clonado bit a bit con hashes MD5/SHA-256 al vuelo para Autopsy
    7. Analizar en Autopsy     lanza Autopsy y prepara el hash de verificación
    8. Particionar/Formatear   crea tabla GPT/partición y formatea (ext4, exfat, fat32, ntfs)
    9. Auditoría Particiones   revela particiones ocultas, flags, espacio no asignado y montaje RO
    ▶  Diagnóstico completo    encadena las pruebas y emite un veredicto

Seguridad:
    - Nunca se usa shell=True: los comandos son listas de argumentos.
    - Solo se pueden elegir unidades detectadas por lsblk (no se teclea nada).
    - Los discos con el sistema montado (/, /boot, /home...) tienen bloqueadas las operaciones destructivas.
"""
import hashlib
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from tkinter import filedialog, messagebox

import customtkinter as ctk

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

MIB = 1024 * 1024
PKEXEC = shutil.which("pkexec") or "pkexec"
SH = "/bin/sh"
FUENTE = ("DejaVu Sans Mono", 12)

PAQUETES = {
    "smartctl": "smartmontools",
    "badblocks": "e2fsprogs",
    "dd": "coreutils",
    "lsblk": "util-linux",
    "blkid": "util-linux",
    "pkexec": "policykit-1 (o polkit)",
    "f3probe": "f3",
    "udisksctl": "udisks2",
    "autopsy": "autopsy",
    "parted": "parted",
    "wipefs": "util-linux",
    "mkfs.ext4": "e2fsprogs",
    "mkfs.vfat": "dosfstools",
    "mkfs.exfat": "exfatprogs",
    "mkfs.ntfs": "ntfs-3g",
}

RE_BB = re.compile(r"(\d+(?:\.\d+)?)% done, ([\d:]+) elapsed\. \((\d+)/(\d+)/(\d+) errors\)")
RE_DD = re.compile(r"([\d.,]+)\s*([kKMG]?)B/s")
RE_CLONE = re.compile(r"@@PROG (\d+) (\d+) ([\d.]+)")

COLS_NUEVO = "NAME,PATH,VENDOR,MODEL,SERIAL,SIZE,TRAN,RM,HOTPLUG,ROTA,TYPE,FSTYPE,LABEL,MOUNTPOINTS"
COLS_VIEJO = COLS_NUEVO.replace("MOUNTPOINTS", "MOUNTPOINT")
MONTAJES_SISTEMA = {"/", "/boot", "/boot/efi", "/usr", "/var", "/home", "[SWAP]"}

ATTR_INTERES = [
    "Reallocated_Sector_Ct", "Reallocated_Event_Count", "Current_Pending_Sector",
    "Offline_Uncorrectable", "Reported_Uncorrect", "UDMA_CRC_Error_Count",
    "Spin_Retry_Count", "Power_Cycle_Count", "Wear_Leveling_Count",
    "Media_Wearout_Indicator", "Percent_Lifetime_Remain",
]
ATTR_CRITICOS = {
    "Reallocated_Sector_Ct", "Reallocated_Event_Count", "Current_Pending_Sector",
    "Offline_Uncorrectable", "Reported_Uncorrect", "UDMA_CRC_Error_Count", "Spin_Retry_Count",
}


class Cancelado(Exception):
    pass


class ErrorAuth(Exception):
    pass


# ───────────────────────── utilidades ─────────────────────────

def fmt_tam(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1000


def fmt_seg(s):
    s = int(max(0, s))
    h, r = divmod(s, 3600)
    m, sec = divmod(r, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{sec:02d}s"


def parse_dd(texto):
    """Devuelve la velocidad en MB/s (decimales) del último resumen de dd, o None."""
    m = RE_DD.findall(texto)
    if not m:
        return None
    val, pref = m[-1]
    try:
        v = float(val.replace(",", "."))
    except ValueError:
        return None
    return v * {"": 1e-6, "k": 1e-3, "K": 1e-3, "M": 1.0, "G": 1e3}[pref]


def extraer_json(texto):
    i, j = texto.find("{"), texto.rfind("}")
    if i < 0 or j <= i:
        return None
    try:
        return json.loads(texto[i:j + 1])
    except ValueError:
        return None


def si(v):
    return str(v).lower() in ("1", "true")


def leer_lsblk():
    for cols in (COLS_NUEVO, COLS_VIEJO):
        try:
            r = subprocess.run(["lsblk", "-J", "-b", "-o", cols], capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            return []
        if r.returncode == 0 and r.stdout.strip():
            try:
                return json.loads(r.stdout)["blockdevices"]
            except (ValueError, KeyError):
                return []
    return []


def montajes(n):
    v = n.get("mountpoints")
    if v is None:
        v = [n.get("mountpoint")]
    return [m for m in v if m]


def recolectar(nodo, parts, mounts):
    for ch in nodo.get("children") or []:
        parts.append({
            "path": ch.get("path") or f"/dev/{ch.get('name')}",
            "fstype": ch.get("fstype") or "",
            "label": ch.get("label") or "",
            "size": int(ch.get("size") or 0),
            "mounts": montajes(ch),
        })
        mounts.extend(montajes(ch))
        recolectar(ch, parts, mounts)


def descubrir(todos=False):
    salida = []
    for n in leer_lsblk():
        if n.get("type") != "disk":
            continue
        parts, mounts = [], montajes(n)
        recolectar(n, parts, mounts)
        tran = (n.get("tran") or "").lower()
        extraible = tran == "usb" or si(n.get("rm")) or si(n.get("hotplug"))
        if not todos and not extraible:
            continue
        montadas = [(p["path"], p["mounts"]) for p in parts if p["mounts"]]
        if montajes(n):
            montadas.append((n.get("path") or f"/dev/{n.get('name')}", montajes(n)))
        salida.append({
            "path": n.get("path") or f"/dev/{n.get('name')}",
            "vendor": (n.get("vendor") or "").strip(),
            "model": (n.get("model") or "").strip(),
            "serial": (n.get("serial") or "").strip(),
            "size": int(n.get("size") or 0),
            "tran": tran,
            "rota": si(n.get("rota")),
            "parts": parts,
            "mounts": mounts,
            "montadas": montadas,
            "extraible": extraible,
            "sistema": any(m in MONTAJES_SISTEMA or m.startswith("/boot") for m in mounts),
        })
    return salida


def nombre_disco(d):
    return " ".join(x for x in (d["vendor"], d["model"]) if x) or "Dispositivo sin nombre"


def etiqueta(d):
    t = f"{d['path']}  ·  {nombre_disco(d)}  ·  {fmt_tam(d['size'])}"
    if d["tran"]:
        t += f"  ·  {d['tran']}"
    if d["sistema"]:
        t += "  ·  SISTEMA"
    return t


def ident(d):
    return (d["path"], d["serial"], d["size"]) if d else None


def firma(lista):
    return tuple((d["path"], d["serial"], d["size"], tuple(d["mounts"])) for d in lista)


def info_texto(d):
    if not d:
        return "Conecta una unidad USB o marca «Mostrar todos los discos» y pulsa «Refrescar»."
    tipo = "HDD (giratorio)" if d["rota"] else "SSD / memoria flash"
    L = [
        f"Dispositivo : {d['path']}   ({nombre_disco(d)})",
        f"Serie       : {d['serial'] or 'no disponible'}",
        f"Capacidad   : {fmt_tam(d['size'])} (anunciada)   Bus: {d['tran'] or '?'}   Tipo: {tipo}",
    ]
    if d["sistema"]:
        L.append("⚠ Contiene el sistema: solo se permiten operaciones de lectura y clonado.")
    if d["parts"]:
        L.append("Particiones :")
        for p in d["parts"]:
            fs = p["fstype"] or "sin formato"
            et = f" «{p['label']}»" if p["label"] else ""
            mp = f" → {', '.join(p['mounts'])}" if p["mounts"] else " (sin montar)"
            L.append(f"   {p['path']}  {fs}{et}  {fmt_tam(p['size'])}{mp}")
    else:
        L.append("Particiones : ninguna detectada")
    return "\n".join(L)


# ───────────────────────── diálogo de formateo/particionado ─────────────────────────

class DialogoFormateo(ctk.CTkToplevel):
    """Ventana modal para configurar tabla de particiones, sistema de archivos y etiqueta."""

    def __init__(self, parent, disco):
        super().__init__(parent)
        self.withdraw()
        self.title("Particionar y Formatear Unidad")
        self.geometry("520x450")
        self.resizable(False, False)
        self.disco = disco
        self.resultado = None

        self.transient(parent)

        ctk.CTkLabel(
            self,
            text=f"DESTINO: {disco['path']} ({nombre_disco(disco)})",
            font=(FUENTE[0], 13, "bold"),
            text_color="#FF5555"
        ).pack(pady=(14, 2))
        ctk.CTkLabel(
            self,
            text=f"Capacidad total: {fmt_tam(disco['size'])}",
            font=FUENTE,
            text_color="#AAAAAA"
        ).pack(pady=(0, 10))

        f_modo = ctk.CTkFrame(self)
        f_modo.pack(fill="x", padx=16, pady=6)
        ctk.CTkLabel(f_modo, text="1. Esquema de Particiones:", font=(FUENTE[0], 12, "bold")).pack(anchor="w", padx=10, pady=(8, 4))

        self.var_modo = ctk.StringVar(value="gpt_unica")
        ctk.CTkRadioButton(
            f_modo,
            text="Crear tabla GPT nueva + 1 partición primaria (borra todo)",
            variable=self.var_modo,
            value="gpt_unica",
            font=FUENTE,
            command=self._actualizar_objetivos
        ).pack(anchor="w", padx=16, pady=3)

        self.rb_part = ctk.CTkRadioButton(
            f_modo,
            text="Formatear solo una partición existente",
            variable=self.var_modo,
            value="solo_particion",
            font=FUENTE,
            command=self._actualizar_objetivos
        )
        self.rb_part.pack(anchor="w", padx=16, pady=(3, 8))

        part_paths = [p["path"] for p in disco["parts"]]
        self.var_part = ctk.StringVar(value=part_paths[0] if part_paths else "(sin particiones)")
        self.menu_part = ctk.CTkOptionMenu(
            f_modo,
            values=part_paths or ["(sin particiones)"],
            variable=self.var_part,
            font=FUENTE,
            width=260
        )
        self.menu_part.pack(anchor="w", padx=36, pady=(0, 10))

        if not part_paths:
            self.rb_part.configure(state="disabled")
            self.menu_part.configure(state="disabled")

        f_fs = ctk.CTkFrame(self)
        f_fs.pack(fill="x", padx=16, pady=6)
        ctk.CTkLabel(f_fs, text="2. Sistema de Archivos y Etiqueta:", font=(FUENTE[0], 12, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(8, 6)
        )

        ctk.CTkLabel(f_fs, text="Formato:", font=FUENTE).grid(row=1, column=0, sticky="w", padx=14, pady=6)
        self.var_fs = ctk.StringVar(value="ext4")
        self.menu_fs = ctk.CTkOptionMenu(
            f_fs,
            values=["ext4", "exfat", "fat32", "ntfs"],
            variable=self.var_fs,
            font=FUENTE,
            width=200
        )
        self.menu_fs.grid(row=1, column=1, sticky="w", padx=10, pady=6)

        ctk.CTkLabel(f_fs, text="Etiqueta:", font=FUENTE).grid(row=2, column=0, sticky="w", padx=14, pady=(6, 12))
        self.entry_label = ctk.CTkEntry(f_fs, font=FUENTE, width=200, placeholder_text="Ej. DATOS_USB")
        self.entry_label.grid(row=2, column=1, sticky="w", padx=10, pady=(6, 12))

        f_btn = ctk.CTkFrame(self, fg_color="transparent")
        f_btn.pack(fill="x", padx=16, pady=(14, 10))
        ctk.CTkButton(
            f_btn,
            text="Cancelar",
            font=FUENTE,
            fg_color="#444444",
            hover_color="#666666",
            width=120,
            command=self.destroy
        ).pack(side="right", padx=6)

        ctk.CTkButton(
            f_btn,
            text="⚠ Ejecutar Formateo",
            font=(FUENTE[0], 12, "bold"),
            fg_color="#8B0000",
            hover_color="#B22222",
            width=180,
            command=self._confirmar
        ).pack(side="right", padx=6)

        self._actualizar_objetivos()

        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() // 2) - (self.winfo_width() // 2)
        y = parent.winfo_rooty() + (parent.winfo_height() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{max(0, x)}+{max(0, y)}")
        self.deiconify()
        self.after(60, self._capturar_foco)

    def _capturar_foco(self):
        try:
            self.lift()
            self.focus_force()
            self.grab_set()
        except Exception:
            pass

    def _actualizar_objetivos(self):
        if self.var_modo.get() == "solo_particion" and self.disco["parts"]:
            self.menu_part.configure(state="normal")
        else:
            self.menu_part.configure(state="disabled")

    def _confirmar(self):
        modo = self.var_modo.get()
        fs = self.var_fs.get()
        etiqueta_raw = self.entry_label.get().strip()
        etiqueta_limpia = re.sub(r"[^A-Za-z0-9_-]", "", etiqueta_raw)

        objetivo = self.disco["path"] if modo == "gpt_unica" else self.var_part.get()
        desc_accion = (
            f"BORRAR TODA LA TABLA DE PARTICIONES de {self.disco['path']}, crear 1 partición GPT nueva y formatearla en {fs.upper()}"
            if modo == "gpt_unica"
            else f"FORMATEAR la partición {objetivo} en {fs.upper()}"
        )

        if not messagebox.askyesno(
            "CONFIRMACIÓN DESTRUCTIVA",
            f"¡ATENCIÓN! Se perderán TODOS los datos actuales.\n\n"
            f"Acción: {desc_accion}\n"
            f"Etiqueta: {etiqueta_limpia or '(ninguna)'}\n\n"
            f"¿Estás completamente seguro de continuar?",
            parent=self
        ):
            return

        self.resultado = {
            "modo": modo,
            "objetivo": objetivo,
            "fs": fs,
            "label": etiqueta_limpia,
        }
        self.destroy()


# ───────────────────────── diálogo de auditoría de particiones (ocultas/visibles) ─────────────────────────

class DialogoParticiones(ctk.CTkToplevel):
    """Muestra todas las particiones (incluidas ocultas, flags y huecos) y permite montaje RO."""

    def __init__(self, parent, disco, datos_particiones):
        super().__init__(parent)
        self.withdraw()
        self.title(f"Auditoría de Particiones // {disco['path']}")
        self.geometry("820x520")
        self.resizable(True, True)
        self.parent = parent
        self.disco = disco
        self.datos = datos_particiones  # lista de dicts con info completa
        self.montajes_ro_activos = []   # [(part_path, tmp_dir), ...]

        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self._cerrar)

        ctk.CTkLabel(
            self,
            text=f"MAPA DE PARTICIONES (VISIBLES Y OCULTAS) · {disco['path']} ({nombre_disco(disco)})",
            font=(FUENTE[0], 13, "bold"),
            text_color="#55CCFF"
        ).pack(pady=(12, 2))

        ctk.CTkLabel(
            self,
            text=f"Tabla: {datos_particiones['tabla'].upper()}  ·  Capacidad real: {fmt_tam(disco['size'])} ({disco['size']} bytes)",
            font=FUENTE,
            text_color="#AAAAAA"
        ).pack(pady=(0, 8))

        # Área de detalle técnico
        self.txt_mapa = ctk.CTkTextbox(self, font=FUENTE, fg_color="#0A0A0A", text_color="#C8FFC8")
        self.txt_mapa.pack(fill="both", expand=True, padx=14, pady=4)
        for tag, color in (("ok", "#00FF66"), ("warn", "#FFCC00"), ("err", "#FF5555"),
                           ("info", "#C8FFC8"), ("dim", "#7A8A7A"), ("head", "#55CCFF")):
            self.txt_mapa.tag_config(tag, foreground=color)

        self._poblar_texto()

        # Barra inferior de montaje seguro en Solo Lectura (RO)
        f_ro = ctk.CTkFrame(self)
        f_ro.pack(fill="x", padx=14, pady=(6, 12))

        ctk.CTkLabel(f_ro, text="Inspección Forense (Solo Lectura):", font=(FUENTE[0], 12, "bold")).pack(
            side="left", padx=(10, 6), pady=8
        )

        part_nodes = [p["node"] for p in datos_particiones["items"] if p["tipo"] == "particion"]
        self.var_sel_part = ctk.StringVar(value=part_nodes[0] if part_nodes else "(ninguna)")
        self.menu_ro = ctk.CTkOptionMenu(
            f_ro,
            values=part_nodes or ["(ninguna)"],
            variable=self.var_sel_part,
            font=FUENTE,
            width=180
        )
        self.menu_ro.pack(side="left", padx=4, pady=8)

        self.btn_montar_ro = ctk.CTkButton(
            f_ro,
            text="🔍 Montar RO y Abrir",
            font=(FUENTE[0], 12, "bold"),
            fg_color="#0D47A1",
            hover_color="#1565C0",
            command=self._montar_ro
        )
        self.btn_montar_ro.pack(side="left", padx=6, pady=8)

        if not part_nodes:
            self.menu_ro.configure(state="disabled")
            self.btn_montar_ro.configure(state="disabled")

        ctk.CTkButton(
            f_ro,
            text="Cerrar (y desmontar RO)",
            font=FUENTE,
            fg_color="#444444",
            hover_color="#666666",
            command=self._cerrar
        ).pack(side="right", padx=10, pady=8)

        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() // 2) - (self.winfo_width() // 2)
        y = parent.winfo_rooty() + (parent.winfo_height() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{max(0, x)}+{max(0, y)}")
        self.deiconify()
        self.after(60, self._capturar_foco)

    def _capturar_foco(self):
        try:
            self.lift()
            self.focus_force()
            self.grab_set()
        except Exception:
            pass

    def _poblar_texto(self):
        self.txt_mapa.configure(state="normal")
        self.txt_mapa.delete("1.0", "end")
        items = self.datos["items"]
        if not items:
            self.txt_mapa.insert("end", "No se detectaron particiones ni estructuras válidas en este dispositivo.\n", "warn")
        for it in items:
            if it["tipo"] == "hueco":
                self.txt_mapa.insert(
                    "end",
                    f"[ESPACIO NO ASIGNADO / POSIBLE PARTICIÓN BORRADA]\n"
                    f"   Rango : {it['inicio']} B → {it['fin']} B   |   Tamaño: {fmt_tam(it['tam'])}\n\n",
                    "warn"
                )
            else:
                estado_vis = "OCULTA / SISTEMA" if it["oculta"] else "VISIBLE / ESTÁNDAR"
                tag_vis = "warn" if it["oculta"] else "ok"
                self.txt_mapa.insert("end", f"━━ Partición #{it['num']} : {it['node']}  [{estado_vis}] ━━\n", tag_vis)
                self.txt_mapa.insert("end", f"   Sistema Arch. : {it['fstype'] or 'Desconocido / Cifrado / RAW'}\n", "info")
                self.txt_mapa.insert("end", f"   Etiqueta / Nombre : {it['label'] or '(sin etiqueta)'}  |  PartLabel: {it['partlabel'] or '(ninguno)'}\n", "info")
                self.txt_mapa.insert("end", f"   Tamaño        : {fmt_tam(it['tam'])} ({it['tam']} bytes)\n", "info")
                self.txt_mapa.insert("end", f"   Offsets       : {it['inicio']} B → {it['fin']} B\n", "dim")
                self.txt_mapa.insert("end", f"   Flags         : {it['flags'] or '(ninguno)'}\n", "warn" if it["oculta"] else "dim")
                self.txt_mapa.insert("end", f"   UUID          : {it['uuid'] or 'N/A'}\n", "dim")
                self.txt_mapa.insert("end", f"   Montaje actual: {it['mount'] or 'No montada (oculta al explorador)'}\n\n", "info")
        self.txt_mapa.configure(state="disabled")

    def _montar_ro(self):
        nodo = self.var_sel_part.get()
        if not nodo or nodo == "(ninguna)":
            return
        # Verificar si ya está montada por el sistema
        for it in self.datos["items"]:
            if it.get("node") == nodo and it.get("mount"):
                mp_existente = it["mount"].split(",")[0].strip()
                self.parent.log(f"La partición {nodo} ya está montada en {mp_existente}. Abriendo...", "info")
                subprocess.Popen(["xdg-open", mp_existente], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return

        tmp_dir = tempfile.mkdtemp(prefix=f"drivesec_ro_{os.path.basename(nodo)}_")
        self.parent.log(f"Montando {nodo} en modo ESTRICTO SOLO LECTURA en {tmp_dir}...", "head")

        # Intentar montaje forense (ro,noload para evitar replay de journal en ext4/xfs)
        ok = False
        for opts in ("ro,noload", "ro"):
            rc, out = self.parent.correr(["mount", "-o", opts, nodo, tmp_dir], root=True)
            if rc == 0:
                ok = True
                break

        if not ok:
            os.rmdir(tmp_dir)
            messagebox.showerror(
                "Drive-Sec",
                f"No se pudo montar {nodo} en solo lectura.\n"
                f"Puede tratarse de una partición cifrada (BitLocker/LUKS), espacio reservado MSR o datos RAW.\n\n"
                f"Detalle: {out.strip()}",
                parent=self
            )
            return

        self.montajes_ro_activos.append((nodo, tmp_dir))
        self.parent.log(f"Partición {nodo} montada en Solo Lectura: {tmp_dir}", "ok")
        subprocess.Popen(["xdg-open", tmp_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _cerrar(self):
        for nodo, tmp_dir in self.montajes_ro_activos:
            self.parent.correr(["umount", tmp_dir], root=True)
            try:
                os.rmdir(tmp_dir)
            except OSError:
                pass
            self.parent.log(f"Desmontada inspección RO de {nodo}.", "dim")
        self.destroy()


# ───────────────────────── aplicación principal ─────────────────────────

class DriveSec(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Drive-Sec v2.3 // Diagnóstico, Forense y Auditoría de Discos")
        self.geometry("1060x870")
        self.minsize(940, 720)

        self.cola = queue.Queue()
        self.cancelar = threading.Event()
        self.proc = None
        self.root_pid = None
        self.ocupado = False
        self.discos = {}
        self.disco = None
        self.res = {}
        self._firma = None
        self._indet = False
        self.ultimo_veredicto = ""
        self.ultima_imagen = None

        self.construir_interfaz()
        self.protocol("WM_DELETE_WINDOW", self.al_cerrar)
        self.verificar_herramientas()
        self.refrescar(inicial=True)
        self.after(80, self.procesar_cola)
        self.after(4000, self.auto_refrescar)

    # ───── interfaz ─────

    def construir_interfaz(self):
        self.var_todos = ctk.BooleanVar(value=False)
        self.var_sup = ctk.BooleanVar(value=False)

        ctk.CTkLabel(self, text="DRIVE-SEC // DIAGNÓSTICO, FORENSE Y AUDITORÍA DE DISCOS",
                     font=(FUENTE[0], 18, "bold"), text_color="#00FF66").pack(pady=(12, 4))

        # Selector de unidad
        f = ctk.CTkFrame(self)
        f.pack(fill="x", padx=14, pady=4)
        self.menu = ctk.CTkOptionMenu(f, values=["(buscando...)"], command=self.al_elegir,
                                      width=600, font=FUENTE, dynamic_resizing=False)
        self.menu.grid(row=0, column=0, padx=8, pady=8)
        self.btn_refrescar = ctk.CTkButton(f, text="↻ Refrescar", width=100, font=FUENTE,
                                           command=self.refrescar)
        self.btn_refrescar.grid(row=0, column=1, padx=4)
        ctk.CTkCheckBox(f, text="Mostrar todos los discos", variable=self.var_todos,
                        command=self.refrescar, font=FUENTE).grid(row=0, column=2, padx=8)

        # Info de la unidad
        fi = ctk.CTkFrame(self)
        fi.pack(fill="x", padx=14, pady=4)
        self.lbl_info = ctk.CTkLabel(fi, text="", font=FUENTE, justify="left", anchor="w")
        self.lbl_info.pack(fill="x", padx=10, pady=8)

        # Botones de pruebas, forense, formateo y auditoría
        fb = ctk.CTkFrame(self)
        fb.pack(fill="x", padx=14, pady=4)
        fb.grid_columnconfigure((0, 1, 2), weight=1)
        morado = ("#4B0082", "#6A2BA8")
        rojo = ("#8B0000", "#B22222")
        azul_forense = ("#0D47A1", "#1565C0")
        cyan_autopsy = ("#006064", "#00838F")
        naranja_fmt = ("#B34700", "#D95B00")
        teal_audit = ("#1B5E20", "#2E7D32")

        defs = [
            ("1 · Salud S.M.A.R.T.", "smart", None),
            ("2 · Velocidad de lectura", "lectura", None),
            ("3 · Velocidad de escritura", "escritura", None),
            ("4 · Escaneo de superficie", "superficie", morado),
            ("5 · Capacidad real (anti-fraude)", "capacidad", morado),
            ("▶ DIAGNÓSTICO COMPLETO", "completo", rojo),
            ("6 · Clonar Imagen (.dd)", "clonar", azul_forense),
            ("7 · Analizar en Autopsy", "autopsy", cyan_autopsy),
            ("8 · Particionar / Formatear", "formatear", naranja_fmt),
            ("9 · Ver Particiones (Ocultas)", "particiones", teal_audit),
        ]
        self.botones = []
        for i, (texto, clave, color) in enumerate(defs):
            kw = {"fg_color": color[0], "hover_color": color[1]} if color else {}
            b = ctk.CTkButton(fb, text=texto, height=36, font=(FUENTE[0], 12, "bold"),
                              command=lambda c=clave: self.iniciar(c), **kw)
            # Si es el botón 10 (índice 9), que ocupe todo el ancho inferior para simetría
            if i == 9:
                b.grid(row=i // 3, column=0, columnspan=3, padx=6, pady=5, sticky="ew")
            else:
                b.grid(row=i // 3, column=i % 3, padx=6, pady=5, sticky="ew")
            self.botones.append(b)

        # Opciones y acciones auxiliares
        fo = ctk.CTkFrame(self, fg_color="transparent")
        fo.pack(fill="x", padx=14, pady=2)
        ctk.CTkCheckBox(fo, text="Incluir escaneo de superficie en el diagnóstico completo (lento)",
                        variable=self.var_sup, font=FUENTE).pack(side="left", padx=6)
        self.btn_cancelar = ctk.CTkButton(fo, text="✖ Cancelar", width=100, font=FUENTE,
                                          fg_color="#8B0000", hover_color="#B22222",
                                          state="disabled", command=self.cancelar_op)
        self.btn_cancelar.pack(side="right", padx=4)
        b = ctk.CTkButton(fo, text="⏏ Desmontar", width=110, font=FUENTE,
                          command=lambda: self.iniciar("desmontar"))
        b.pack(side="right", padx=4)
        self.botones.append(b)

        # Progreso
        fp = ctk.CTkFrame(self, fg_color="transparent")
        fp.pack(fill="x", padx=14, pady=(6, 0))
        self.barra = ctk.CTkProgressBar(fp)
        self.barra.pack(fill="x", padx=6)
        self.barra.set(0)
        self.lbl_prog = ctk.CTkLabel(fp, text="Listo.", font=FUENTE, anchor="w")
        self.lbl_prog.pack(fill="x", padx=6)

        # Veredicto
        self.lbl_veredicto = ctk.CTkLabel(self, text="", font=(FUENTE[0], 13, "bold"),
                                          anchor="w", justify="left", wraplength=980)
        self.lbl_veredicto.pack(fill="x", padx=20, pady=4)
        self.set_veredicto(None)

        # Consola
        self.consola = ctk.CTkTextbox(self, font=FUENTE, fg_color="#0A0A0A", text_color="#C8FFC8")
        self.consola.pack(fill="both", expand=True, padx=14, pady=4)
        for tag, color in (("ok", "#00FF66"), ("warn", "#FFCC00"), ("err", "#FF5555"),
                           ("info", "#C8FFC8"), ("dim", "#7A8A7A"), ("head", "#55CCFF")):
            self.consola.tag_config(tag, foreground=color)

        fz = ctk.CTkFrame(self, fg_color="transparent")
        fz.pack(fill="x", padx=14, pady=(0, 10))
        ctk.CTkButton(fz, text="💾 Guardar reporte", font=FUENTE, command=self.guardar_reporte).pack(side="left", padx=4)
        ctk.CTkButton(fz, text="Limpiar consola", font=FUENTE, fg_color="#444444", hover_color="#666666",
                      command=lambda: self.consola.delete("1.0", "end")).pack(side="left", padx=4)

    # ───── cola de mensajes (hilos → interfaz) ─────

    def log(self, txt, nivel="info"):
        hora = datetime.now().strftime("%H:%M:%S")
        for linea in (str(txt).splitlines() or [""]):
            self.cola.put(("log", hora, linea, nivel))

    def prog(self, frac, txt=""):
        self.cola.put(("prog", frac, txt))

    def procesar_cola(self):
        try:
            while True:
                try:
                    m = self.cola.get_nowait()
                except queue.Empty:
                    break
                k = m[0]
                if k == "log":
                    self.consola.insert("end", f"[{m[1]}] {m[2]}\n", m[3])
                    self.consola.see("end")
                elif k == "prog":
                    self._progreso(m[1], m[2])
                elif k == "fin":
                    self._fin()
                elif k == "refrescar":
                    self.refrescar()
                elif k == "abrir_particiones":
                    DialogoParticiones(self, m[1], m[2])
        finally:
            self.after(80, self.procesar_cola)

    def _progreso(self, frac, txt):
        if txt:
            self.lbl_prog.configure(text=txt)
        if frac is None:
            if not self._indet:
                self.barra.configure(mode="indeterminate")
                self.barra.start()
                self._indet = True
        else:
            if self._indet:
                self.barra.stop()
                self.barra.configure(mode="determinate")
                self._indet = False
            self.barra.set(max(0.0, min(1.0, frac)))

    def _fin(self):
        self.ocupado = False
        self.set_botones(True)
        self._progreso(0, "Listo.")
        self.set_veredicto(self.evaluar())

    def set_botones(self, activo):
        estado = "normal" if activo else "disabled"
        for b in self.botones:
            b.configure(state=estado)
        self.menu.configure(state=estado)
        self.btn_refrescar.configure(state=estado)
        self.btn_cancelar.configure(state="disabled" if activo else "normal")

    def set_veredicto(self, v):
        if not v:
            self.ultimo_veredicto = ""
            self.lbl_veredicto.configure(text="VEREDICTO: sin pruebas ejecutadas todavía", text_color="#888888")
            return
        nivel, texto = v
        color = {"riesgo": "#FF5555", "atencion": "#FFCC00", "ok": "#00FF66"}[nivel]
        self.ultimo_veredicto = f"VEREDICTO: {texto}"
        self.lbl_veredicto.configure(text=self.ultimo_veredicto, text_color=color)

    # ───── detección de unidades ─────

    def refrescar(self, inicial=False):
        self._aplicar_lista(descubrir(self.var_todos.get()), avisar=not inicial)

    def auto_refrescar(self):
        try:
            if not self.ocupado:
                lista = descubrir(self.var_todos.get())
                if firma(lista) != self._firma:
                    self._aplicar_lista(lista, avisar=True)
        finally:
            self.after(4000, self.auto_refrescar)

    def _aplicar_lista(self, lista, avisar=True):
        previo = ident(self.disco)
        self.discos = {etiqueta(d): d for d in lista}
        etqs = list(self.discos) or ["(sin unidades detectadas)"]
        self.menu.configure(values=etqs)
        elegido = next((e for e, d in self.discos.items() if ident(d) == previo), None)
        if elegido is None and self.discos:
            elegido = next(iter(self.discos))
        nuevo = self.discos.get(elegido) if elegido else None
        if avisar and previo and ident(nuevo) != previo:
            self.log(f"La unidad {previo[0]} ya no está disponible.", "warn")
        if ident(nuevo) != previo:
            self.res = {}
            self.set_veredicto(None)
            if nuevo:
                self.log(f"Unidad seleccionada: {etiqueta(nuevo)}", "dim")
        self.disco = nuevo
        self.menu.set(elegido or etqs[0])
        self._firma = firma(lista)
        self.lbl_info.configure(text=info_texto(nuevo))

    def al_elegir(self, etq):
        d = self.discos.get(etq)
        if d:
            self.disco = d
            self.res = {}
            self.set_veredicto(None)
            self.lbl_info.configure(text=info_texto(d))

    def verificar_herramientas(self):
        faltan = []
        for h in ("lsblk", "pkexec", "smartctl", "badblocks", "dd"):
            if not shutil.which(h):
                faltan.append(h)
        opcionales = [h for h in ("f3probe", "udisksctl", "autopsy", "parted", "wipefs") if not shutil.which(h)]
        self.log("Drive-Sec v2.3 listo.", "head")
        if faltan:
            self.log("Faltan herramientas base: " + ", ".join(f"{h} ({PAQUETES[h]})" for h in faltan), "err")
        if opcionales:
            self.log("Opcionales no instaladas: " + ", ".join(f"{h} ({PAQUETES[h]})" for h in opcionales), "warn")
        if not faltan and not opcionales:
            self.log("Todas las herramientas base, forenses y de auditoría están instaladas.", "ok")

    # ───── ejecución de comandos ─────

    def correr(self, args, root=False, on_text=None):
        """Ejecuta sin shell. Devuelve (código, salida). Lanza Cancelado / ErrorAuth."""
        if self.cancelar.is_set():
            raise Cancelado()
        cmd = list(args)
        if root:
            cmd = [PKEXEC, SH, "-c", 'echo "__PID__$$"; exec "$@"', "sh"] + cmd
        env = {**os.environ, "LC_ALL": "C"}
        self.root_pid = None
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, env=env, bufsize=0)
        fd = self.proc.stdout.fileno()
        partes, pend = [], ""
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            txt = chunk.decode("utf-8", "replace")
            if root and self.root_pid is None:
                pend += txt
                m = re.search(r"__PID__(\d+)\r?\n", pend)
                if m:
                    self.root_pid = int(m.group(1))
                    txt = pend[:m.start()] + pend[m.end():]
                    pend = ""
                elif len(pend) < 200:
                    continue
                else:
                    txt, pend = pend, ""
            partes.append(txt)
            if on_text and txt:
                on_text(txt)
        if pend:
            partes.append(pend)
        rc = self.proc.wait()
        sin_pid = self.root_pid is None
        self.proc = None
        salida = "".join(partes)
        if self.cancelar.is_set():
            raise Cancelado()
        if root and rc in (126, 127) and sin_pid:
            raise ErrorAuth(salida.strip()[-200:] or "pkexec devolvió un error")
        return rc, salida

    def _matar(self):
        p, pid = self.proc, self.root_pid
        if not p or p.poll() is not None:
            return

        def tarea():
            if pid:
                subprocess.run([PKEXEC, SH, "-c", f"pkill -TERM -P {pid}; kill -TERM {pid}"],
                               capture_output=True)
            try:
                p.terminate()
            except OSError:
                pass

        threading.Thread(target=tarea, daemon=True).start()

    def cancelar_op(self):
        if self.ocupado:
            self.cancelar.set()
            self.log("Cancelando... (si usaba privilegios puede pedir la contraseña otra vez)", "warn")
            self._matar()

    def al_cerrar(self):
        if self.ocupado:
            if not messagebox.askyesno("Drive-Sec", "Hay una operación en curso. ¿Cancelarla y salir?"):
                return
            self.cancelar.set()
            self._matar()
        self.destroy()

    # ───── lanzar pruebas y operaciones ─────

    def iniciar(self, clave):
        if self.ocupado:
            return

        if clave == "autopsy":
            if not shutil.which("autopsy"):
                messagebox.showerror("Drive-Sec", "Autopsy no está instalado.\n\nInstala: sudo apt install autopsy")
                return
            self.lanzar_autopsy()
            return

        d = self.disco
        if not d:
            messagebox.showwarning("Drive-Sec", "Selecciona una unidad primero.")
            return

        herramientas = {
            "smart": ["smartctl"], "lectura": ["dd"], "escritura": ["dd"],
            "superficie": ["badblocks"], "capacidad": ["f3probe"],
            "completo": ["smartctl", "dd"], "desmontar": [], "clonar": [],
            "formatear": ["parted", "wipefs"], "particiones": ["parted", "lsblk"],
        }[clave]
        if clave not in ("escritura", "desmontar"):
            herramientas = herramientas + ["pkexec"]
        faltan = [h for h in herramientas if not shutil.which(h)]
        if faltan:
            pk = " ".join(PAQUETES[h] for h in faltan)
            messagebox.showerror("Drive-Sec", f"Falta: {', '.join(faltan)}\n\nInstala: sudo apt install {pk}")
            return

        if d["sistema"] and clave in ("escritura", "superficie", "capacidad", "desmontar", "formatear"):
            messagebox.showwarning("Drive-Sec", "Esta unidad contiene el sistema en uso.\n"
                                   "Esa operación está bloqueada por seguridad.")
            return

        ident_txt = f"{d['path']} ({nombre_disco(d)}, {fmt_tam(d['size'])})"
        incluir_sup = self.var_sup.get()

        if clave == "formatear":
            dlg = DialogoFormateo(self, d)
            self.wait_window(dlg)
            if not dlg.resultado:
                return
            cfg = dlg.resultado
            mkfs_bin = {
                "ext4": "mkfs.ext4",
                "exfat": "mkfs.exfat",
                "fat32": "mkfs.vfat",
                "ntfs": "mkfs.ntfs",
            }[cfg["fs"]]
            if not shutil.which(mkfs_bin):
                messagebox.showerror("Drive-Sec", f"Falta {mkfs_bin}.\n\nInstala: sudo apt install {PAQUETES[mkfs_bin]}")
                return
            self.lanzar(f"Formateo ({cfg['fs'].upper()})", lambda: self.tarea_formatear(d, cfg), d)
            return

        if clave == "escritura":
            if not any(os.access(m, os.W_OK) for m in d["mounts"]):
                messagebox.showinfo("Drive-Sec", "La prueba de escritura necesita una partición montada "
                                    "con permiso de escritura.")
                return
            if not messagebox.askyesno("Drive-Sec", "Se escribirá un archivo temporal (hasta 256 MiB) en la "
                                       "unidad y se borrará al terminar.\n\n¿Continuar?"):
                return
        elif clave == "superficie":
            if not messagebox.askyesno("Drive-Sec", f"Escaneo de SOLO LECTURA sobre:\n{ident_txt}\n\n"
                                       "Puede tardar desde minutos hasta horas según el tamaño.\n"
                                       "¿Es la unidad correcta?"):
                return
        elif clave == "capacidad":
            if d["mounts"]:
                messagebox.showwarning("Drive-Sec", "La unidad está montada. Pulsa «Desmontar» primero.")
                return
            if not messagebox.askyesno("Drive-Sec", f"f3probe escribirá y leerá bloques de prueba en:\n{ident_txt}\n\n"
                                       "Por defecto intenta preservar los datos, pero conviene tener "
                                       "respaldo si son importantes.\n¿Continuar?"):
                return
        elif clave == "completo":
            extra = "\n+ escaneo de superficie (lento)" if incluir_sup and not d["sistema"] else ""
            if not messagebox.askyesno("Drive-Sec", f"Diagnóstico completo de:\n{ident_txt}{extra}\n\n"
                                       "Es posible que se pida la contraseña de administrador varias veces.\n"
                                       "¿Continuar?"):
                return
        elif clave == "clonar":
            if d["size"] <= 0:
                messagebox.showerror("Drive-Sec", "No se detecta capacidad válida en el dispositivo.")
                return
            if d["mounts"]:
                if not messagebox.askyesno("Drive-Sec — Rigor Forense",
                                           "⚠ La unidad origen tiene particiones montadas.\n"
                                           "En forense digital se recomienda desmontarla antes para evitar escrituras "
                                           "del sistema operativo durante la adquisición.\n\n"
                                           "¿Deseas continuar de todos modos?"):
                    return
            base = d["path"].replace("/dev/", "")
            ruta_destino = filedialog.asksaveasfilename(
                title="Guardar imagen forense RAW (.dd)",
                defaultextension=".dd",
                filetypes=[("Imagen RAW Forense", "*.dd"), ("Imagen Binaria", "*.img"), ("Todos", "*.*")],
                initialfile=f"evidencia_{base}_{datetime.now():%Y%m%d_%H%M}.dd"
            )
            if not ruta_destino:
                return

            dir_dest = os.path.realpath(os.path.dirname(ruta_destino))
            for mp in d["mounts"]:
                mp_real = os.path.realpath(mp)
                if dir_dest == mp_real or dir_dest.startswith(mp_real + os.sep):
                    messagebox.showerror("Drive-Sec", "ERROR CRÍTICO: No puedes guardar la imagen dentro "
                                         "del mismo disco que estás clonando.")
                    return

            libre_dest = shutil.disk_usage(dir_dest).free
            if libre_dest < d["size"]:
                messagebox.showerror("Drive-Sec", f"Espacio insuficiente en destino.\n"
                                     f"Requerido: {fmt_tam(d['size'])}\n"
                                     f"Disponible: {fmt_tam(libre_dest)}")
                return

            self.lanzar("Adquisición Forense (.dd)", lambda: self.tarea_clonar(d, ruta_destino), d)
            return

        nombres = {"smart": "S.M.A.R.T.", "lectura": "Velocidad de lectura", "escritura": "Velocidad de escritura",
                   "superficie": "Escaneo de superficie", "capacidad": "Capacidad real",
                   "completo": "Diagnóstico completo", "desmontar": "Desmontar",
                   "particiones": "Auditoría de Particiones"}
        funciones = {"smart": self.tarea_smart, "lectura": self.tarea_lectura, "escritura": self.tarea_escritura,
                     "superficie": self.tarea_superficie, "capacidad": self.tarea_capacidad,
                     "desmontar": self.tarea_desmontar, "particiones": self.tarea_auditar_particiones}
        if clave == "completo":
            self.lanzar(nombres[clave], lambda: self.tarea_completo(d, incluir_sup), d)
        else:
            self.lanzar(nombres[clave], lambda: funciones[clave](d), d)

    def lanzar(self, nombre, fn, d):
        self.cancelar.clear()
        self.ocupado = True
        self.set_botones(False)
        self.log(f"━━ {nombre} · {d['path']} · {nombre_disco(d)} ━━", "head")

        def run():
            try:
                fn()
            except Cancelado:
                self.log("Operación cancelada por el usuario.", "warn")
            except ErrorAuth as e:
                self.log(f"No se pudo obtener privilegios: {e}", "err")
            except FileNotFoundError as e:
                self.log(f"Herramienta no encontrada: {e.filename}", "err")
            except Exception as e:  # noqa: BLE001
                self.log(f"Error inesperado: {e!r}", "err")
            finally:
                v = self.evaluar()
                if v:
                    self.log(f"VEREDICTO: {v[1]}", {"riesgo": "err", "atencion": "warn", "ok": "ok"}[v[0]])
                self.cola.put(("fin",))

        threading.Thread(target=run, daemon=True).start()

    # ───── módulo de auditoría de particiones (visibles y ocultas) ─────

    def tarea_auditar_particiones(self, d):
        dev = d["path"]
        self.prog(None, f"Inspeccionando tabla de particiones cruda en {dev}...")

        # 1. Leer tabla con parted en modo máquina (-m) y unidades en Bytes (unit B)
        rc_p, out_p = self.correr(["parted", "-m", "-s", dev, "unit", "B", "print", "free"], root=True)

        # 2. Complementar con lsblk profundo (UUID, PARTLABEL, FSTYPE, FLAGS)
        cols_prof = "NAME,PATH,PARTN,FSTYPE,LABEL,PARTLABEL,PARTFLAGS,UUID,SIZE,MOUNTPOINTS"
        r_ls = subprocess.run(["lsblk", "-J", "-b", "-o", cols_prof, dev], capture_output=True, text=True)
        ls_map = {}
        if r_ls.returncode == 0:
            j = extraer_json(r_ls.stdout)
            if j and j.get("blockdevices"):
                for ch in j["blockdevices"][0].get("children") or []:
                    p_node = ch.get("path") or f"/dev/{ch.get('name')}"
                    ls_map[p_node] = ch

        tabla_tipo = "desconocida"
        items = []
        sufijo_base = "p" if dev[-1].isdigit() else ""

        for linea in out_p.splitlines():
            linea = linea.strip().rstrip(";")
            if not linea or linea == "BYT":
                continue
            campos = linea.split(":")
            # Línea cabecera del disco: /dev/sdX:31000000000B:scsi:512:512:msdos:Modelo:;
            if campos[0] == dev and len(campos) >= 6:
                tabla_tipo = campos[5]
                continue

            # Línea de partición o hueco: num:inicioB:finB:tamB:fs:nombre:flags
            if len(campos) >= 5 and campos[1].endswith("B"):
                num_str = campos[0]
                inicio = int(campos[1].rstrip("B"))
                fin = int(campos[2].rstrip("B"))
                tam = int(campos[3].rstrip("B"))
                fs_parted = campos[4]

                if fs_parted == "free":
                    # Ignorar alineaciones menores a 2 MiB
                    if tam >= 2 * MIB:
                        items.append({
                            "tipo": "hueco",
                            "inicio": inicio,
                            "fin": fin,
                            "tam": tam,
                        })
                    continue

                nodo = f"{dev}{sufijo_base}{num_str}"
                partlabel = campos[5] if len(campos) > 5 else ""
                flags = campos[6] if len(campos) > 6 else ""

                extra = ls_map.get(nodo, {})
                fstype = extra.get("fstype") or fs_parted
                label = extra.get("label") or ""
                partlabel = extra.get("partlabel") or partlabel
                uuid = extra.get("uuid") or ""
                mps = montajes(extra)
                mount_str = ", ".join(mps)

                # Detectar si está oculta o reservada
                flags_low = flags.lower()
                es_oculta = (
                    "hidden" in flags_low
                    or "msftres" in flags_low
                    or "diag" in flags_low
                    or "esp" in flags_low
                    or not mount_str
                )

                items.append({
                    "tipo": "particion",
                    "num": num_str,
                    "node": nodo,
                    "inicio": inicio,
                    "fin": fin,
                    "tam": tam,
                    "fstype": fstype,
                    "label": label,
                    "partlabel": partlabel,
                    "flags": flags,
                    "uuid": uuid,
                    "mount": mount_str,
                    "oculta": es_oculta,
                })

        # Fallback si parted no pudo leer tabla (ej. formato raw sin tabla MBR/GPT)
        if not items and ls_map:
            for nodo, extra in ls_map.items():
                mps = montajes(extra)
                items.append({
                    "tipo": "particion",
                    "num": str(extra.get("partn") or "?"),
                    "node": nodo,
                    "inicio": 0,
                    "fin": int(extra.get("size") or 0),
                    "tam": int(extra.get("size") or 0),
                    "fstype": extra.get("fstype") or "",
                    "label": extra.get("label") or "",
                    "partlabel": extra.get("partlabel") or "",
                    "flags": str(extra.get("partflags") or ""),
                    "uuid": extra.get("uuid") or "",
                    "mount": ", ".join(mps),
                    "oculta": not bool(mps),
                })

        total_parts = sum(1 for x in items if x["tipo"] == "particion")
        ocultas_cnt = sum(1 for x in items if x["tipo"] == "particion" and x["oculta"])
        huecos_cnt = sum(1 for x in items if x["tipo"] == "hueco")

        self.log(f"Tabla detectada: {tabla_tipo.upper()} | Particiones: {total_parts} ({ocultas_cnt} ocultas/sin montar) | Huecos: {huecos_cnt}", "ok")
        for it in items:
            if it["tipo"] == "hueco":
                self.log(f"   [HUECO NO ASIGNADO] {fmt_tam(it['tam'])} ({it['inicio']} -> {it['fin']})", "warn")
            else:
                tag = "warn" if it["oculta"] else "info"
                fl = f" [flags: {it['flags']}]" if it["flags"] else ""
                self.log(f"   #{it['num']} {it['node']} · {it['fstype'] or 'RAW'} · {fmt_tam(it['tam'])}{fl}", tag)

        self.cola.put(("abrir_particiones", d, {"tabla": tabla_tipo, "items": items}))

    # ───── módulo de particionado y formateo ─────

    def tarea_formatear(self, d, cfg):
        dev_disco = d["path"]
        modo = cfg["modo"]
        fs = cfg["fs"]
        etiqueta_vol = cfg["label"]
        part_objetivo = cfg["objetivo"]

        if d["montadas"]:
            self.prog(0.1, "Desmontando particiones activas...")
            for p_dev, mps in d["montadas"]:
                if shutil.which("udisksctl"):
                    rc, out = self.correr(["udisksctl", "unmount", "-b", p_dev])
                else:
                    rc = 1
                    for mp in mps:
                        rc, out = self.correr(["umount", mp], root=True)
                if rc != 0:
                    self.log(f"No se pudo desmontar {p_dev}: {out.strip()}", "err")
                    return
                self.log(f"Desmontada: {p_dev}", "dim")

        if modo == "gpt_unica":
            self.prog(0.3, f"Limpiando firmas previas en {dev_disco}...")
            rc, out = self.correr(["wipefs", "-a", dev_disco], root=True)
            if rc != 0:
                self.log(f"Error en wipefs: {out.strip()}", "err")
                return

            self.prog(0.5, f"Creando tabla GPT y partición primaria en {dev_disco}...")
            fs_parted = {"ext4": "ext4", "exfat": "ntfs", "fat32": "fat32", "ntfs": "ntfs"}[fs]
            rc, out = self.correr(
                ["parted", "-s", dev_disco, "mklabel", "gpt", "mkpart", "primary", fs_parted, "0%", "100%"],
                root=True
            )
            if rc != 0:
                self.log(f"Error al crear partición con parted: {out.strip()}", "err")
                return

            if shutil.which("partprobe"):
                self.correr(["partprobe", dev_disco], root=True)
            time.sleep(1.5)

            sufijo = "p1" if dev_disco[-1].isdigit() else "1"
            part_objetivo = f"{dev_disco}{sufijo}"
            self.log(f"Tabla GPT creada. Nueva partición objetivo: {part_objetivo}", "info")

        self.prog(0.75, f"Formateando {part_objetivo} como {fs.upper()}...")
        if fs == "ext4":
            cmd_mkfs = ["mkfs.ext4", "-F"]
            if etiqueta_vol:
                cmd_mkfs += ["-L", etiqueta_vol[:16]]
            cmd_mkfs.append(part_objetivo)
        elif fs == "exfat":
            cmd_mkfs = ["mkfs.exfat"]
            if etiqueta_vol:
                cmd_mkfs += ["-n", etiqueta_vol[:15]]
            cmd_mkfs.append(part_objetivo)
        elif fs == "fat32":
            cmd_mkfs = ["mkfs.vfat", "-F", "32"]
            if etiqueta_vol:
                cmd_mkfs += ["-n", etiqueta_vol[:11].upper()]
            cmd_mkfs.append(part_objetivo)
        elif fs == "ntfs":
            cmd_mkfs = ["mkfs.ntfs", "-f"]
            if etiqueta_vol:
                cmd_mkfs += ["-L", etiqueta_vol[:32]]
            cmd_mkfs.append(part_objetivo)

        rc, out = self.correr(cmd_mkfs, root=True)
        if rc != 0:
            self.log(f"Error durante el formateo ({fs}): {out.strip()}", "err")
            return

        if fs == "ext4":
            self.prog(0.9, "Ajustando permisos de propietario en volumen ext4...")
            tmp_mnt = tempfile.mkdtemp(prefix="drivesec_mnt_")
            try:
                rc_m, _ = self.correr(["mount", part_objetivo, tmp_mnt], root=True)
                if rc_m == 0:
                    self.correr(["chown", f"{os.getuid()}:{os.getgid()}", tmp_mnt], root=True)
                    self.correr(["umount", tmp_mnt], root=True)
            finally:
                os.rmdir(tmp_mnt)

        self.prog(1.0, "Formateo completado.")
        self.log(f"Operación exitosa: {part_objetivo} formateado en {fs.upper()}" +
                 (f" con etiqueta «{etiqueta_vol}»." if etiqueta_vol else "."), "ok")
        self.cola.put(("refrescar",))

    # ───── módulo forense: clonado y Autopsy ─────

    def tarea_clonar(self, d, ruta_destino):
        dev = d["path"]
        total_size = d["size"]
        uid, gid = os.getuid(), os.getgid()

        self.log(f"Origen  : {dev} ({fmt_tam(total_size)} / {total_size} bytes)", "info")
        self.log(f"Destino : {ruta_destino}", "info")
        self.log("Calculando hashes MD5 y SHA-256 al vuelo (1 pasada de lectura)...", "dim")
        self.prog(0, "Solicitando privilegios de lectura de bloque...")

        helper_py = (
            "import os, sys, time, hashlib\n"
            "src_p, dst_p, total, uid, gid = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])\n"
            "CHUNK = 4 * 1024 * 1024\n"
            "md5, sha256 = hashlib.md5(), hashlib.sha256()\n"
            "copied, t0, last_print = 0, time.time(), 0.0\n"
            "with open(src_p, 'rb') as src, open(dst_p, 'wb') as dst:\n"
            "    os.chown(dst_p, uid, gid)\n"
            "    while True:\n"
            "        buf = src.read(CHUNK)\n"
            "        if not buf: break\n"
            "        dst.write(buf)\n"
            "        md5.update(buf)\n"
            "        sha256.update(buf)\n"
            "        copied += len(buf)\n"
            "        now = time.time()\n"
            "        if now - last_print >= 0.35:\n"
            "            spd = (copied / 1048576.0) / max(0.001, now - t0)\n"
            "            print(f'@@PROG {copied} {total} {spd:.2f}', flush=True)\n"
            "            last_print = now\n"
            "    dst.flush()\n"
            "    os.fsync(dst.fileno())\n"
            "print(f'@@DONE {copied} {md5.hexdigest()} {sha256.hexdigest()}', flush=True)\n"
        )

        t0 = time.time()
        carry = ""

        def on_text(txt):
            nonlocal carry
            carry = (carry + txt)[-300:]
            for m in RE_CLONE.finditer(carry):
                copied = int(m.group(1))
                tot = int(m.group(2))
                spd = float(m.group(3))
                frac = copied / tot if tot > 0 else 0.0
                rem_mb = (tot - copied) / MIB
                eta = f" · ETA {fmt_seg(rem_mb / spd)}" if spd > 0.1 else ""
                self.prog(frac, f"Clonando {frac * 100:.1f}% ({fmt_tam(copied)}/{fmt_tam(tot)}) · {spd:.1f} MB/s{eta}")

        rc, out = self.correr(
            [sys.executable, "-c", helper_py, dev, ruta_destino, str(total_size), str(uid), str(gid)],
            root=True,
            on_text=on_text
        )

        m_done = re.search(r"@@DONE (\d+) ([0-9a-f]{32}) ([0-9a-f]{64})", out)
        if rc != 0 or not m_done:
            self.log("La clonación falló o quedó incompleta.", "err")
            for line in out.splitlines()[-5:]:
                if not line.startswith("@@"):
                    self.log(f"   {line}", "err")
            return

        bytes_copiados = int(m_done.group(1))
        final_md5 = m_done.group(2)
        final_sha256 = m_done.group(3)
        duracion = time.time() - t0

        self.ultima_imagen = ruta_destino
        self.log("─" * 50, "dim")
        self.log(f"Adquisición completada en {fmt_seg(duracion)} ({bytes_copiados} bytes).", "ok")
        self.log(f"MD5    : {final_md5}", "ok")
        self.log(f"SHA256 : {final_sha256}", "ok")

        log_path = f"{ruta_destino}.log"
        try:
            with open(log_path, "w", encoding="utf-8") as lf:
                lf.write("=== REPORTE DE ADQUISICIÓN FORENSE (DRIVE-SEC) ===\n")
                lf.write(f"Fecha UTC        : {datetime.now(timezone.utc).isoformat()}\n")
                lf.write(f"Estación Forense : {socket.gethostname()}\n")
                lf.write(f"Dispositivo      : {dev} ({nombre_disco(d)})\n")
                lf.write(f"Número de Serie  : {d['serial'] or 'N/A'}\n")
                lf.write(f"Archivo Imagen   : {ruta_destino}\n")
                lf.write(f"Tamaño Copiado   : {bytes_copiados} bytes ({fmt_tam(bytes_copiados)})\n")
                lf.write(f"Tiempo Total     : {duracion:.2f} segundos\n")
                lf.write(f"Hash MD5         : {final_md5}\n")
                lf.write(f"Hash SHA-256     : {final_sha256}\n")
            self.log(f"Cadena de custodia guardada en: {log_path}", "info")
        except OSError as e:
            self.log(f"No se pudo escribir el archivo .log de custodia: {e}", "warn")

        self.log("Listo para análisis: pulsa «7 · Analizar en Autopsy» para abrir.", "head")

    def lanzar_autopsy(self):
        ruta_img = self.ultima_imagen
        if not ruta_img or not os.path.exists(ruta_img):
            ruta_img = filedialog.askopenfilename(
                title="Seleccionar imagen forense (.dd / .img / .E01) para Autopsy",
                filetypes=[("Imágenes Forenses", "*.dd *.img *.raw *.e01 *.E01"), ("Todos", "*.*")]
            )
            if not ruta_img:
                return

        self.log("━━ Iniciando Autopsy Forensics ━━", "head")
        self.log(f"Imagen objetivo : {ruta_img}", "info")

        log_custodia = f"{ruta_img}.log"
        sha_encontrado = None
        if os.path.exists(log_custodia):
            try:
                with open(log_custodia, encoding="utf-8", errors="replace") as lf:
                    for linea in lf:
                        if "Hash SHA-256" in linea and ":" in linea:
                            sha_encontrado = linea.split(":", 1)[1].strip()
                            break
            except OSError:
                pass

        if sha_encontrado:
            self.clipboard_clear()
            self.clipboard_append(sha_encontrado)
            self.log(f"SHA-256 copiado al portapapeles: {sha_encontrado}", "ok")

        self.log("Instrucciones en Autopsy:", "dim")
        self.log("  1. Crea un 'New Case' -> 'Add Data Source' -> 'Disk Image or VM File'.", "dim")
        self.log(f"  2. Selecciona: {ruta_img}", "dim")
        if sha_encontrado:
            self.log("  3. Pega (Ctrl+V) el SHA-256 en el campo de verificación de integridad.", "dim")

        try:
            subprocess.Popen(["autopsy"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
            self.log("Proceso de Autopsy lanzado en segundo plano.", "ok")
        except OSError as e:
            self.log(f"Error al ejecutar Autopsy: {e}", "err")

    # ───── pruebas de diagnóstico ─────

    def tarea_smart(self, d):
        dev = d["path"]
        self.prog(None, "Consultando S.M.A.R.T. (puede pedir contraseña)...")
        datos, usado = None, ""
        for extra in ([], ["-d", "sat"]):
            _, out = self.correr(["smartctl", "-j", "-a", *extra, dev], root=True)
            j = extraer_json(out)
            if j and (j.get("ata_smart_attributes") or j.get("nvme_smart_health_information_log")
                      or j.get("smart_status")):
                datos, usado = j, " ".join(extra)
                break
        if not datos:
            self.log("S.M.A.R.T. no disponible: el adaptador USB o la memoria no lo exponen "
                     "(muy común en pendrives).", "warn")
            self.res["smart"] = None
            return
        if usado:
            self.log(f"(Se usó el modo de paso SAT: smartctl {usado})", "dim")

        modelo = datos.get("model_name") or datos.get("model_family") or "?"
        self.log(f"Modelo: {modelo} · Serie: {datos.get('serial_number', '?')} · "
                 f"Firmware: {datos.get('firmware_version', '?')}", "info")
        rot = datos.get("rotation_rate")
        if "nvme_smart_health_information_log" in datos:
            tipo = "NVMe"
        elif rot == 0:
            tipo = "SSD / flash"
        elif rot:
            tipo = f"HDD {rot} rpm"
        else:
            tipo = "tipo desconocido"
        cap = (datos.get("user_capacity") or {}).get("bytes")
        self.log(f"Tipo: {tipo}" + (f" · Capacidad: {fmt_tam(cap)}" if cap else ""), "info")

        s = {"passed": (datos.get("smart_status") or {}).get("passed")}
        if s["passed"] is True:
            self.log("Evaluación general S.M.A.R.T.: PASSED", "ok")
        elif s["passed"] is False:
            self.log("Evaluación general S.M.A.R.T.: FAILED — la unidad reporta que va a fallar", "err")
        else:
            self.log("El dispositivo no entrega evaluación general S.M.A.R.T.", "warn")

        s["temp"] = (datos.get("temperature") or {}).get("current")
        horas = (datos.get("power_on_time") or {}).get("hours")
        ciclos = datos.get("power_cycle_count")
        linea = []
        if s["temp"] is not None:
            linea.append(f"Temperatura: {s['temp']} °C")
        if horas is not None:
            linea.append(f"Horas encendido: {horas}")
        if ciclos is not None:
            linea.append(f"Ciclos de encendido: {ciclos}")
        if linea:
            self.log(" · ".join(linea), "info")

        attrs = {a["name"]: a for a in (datos.get("ata_smart_attributes") or {}).get("table", [])}

        def raw(*nombres):
            for n in nombres:
                if n in attrs:
                    return attrs[n]["raw"]["value"]
            return None

        s["realoc"] = raw("Reallocated_Sector_Ct") or 0
        s["pendientes"] = (raw("Current_Pending_Sector") or 0) + (raw("Offline_Uncorrectable") or 0)
        s["crc"] = raw("UDMA_CRC_Error_Count") or 0
        for nombre in ATTR_INTERES:
            if nombre in attrs:
                v = attrs[nombre]["raw"]["value"]
                nivel = "warn" if (nombre in ATTR_CRITICOS and v > 0) else "info"
                self.log(f"   {nombre}: {v}", nivel)

        nv = datos.get("nvme_smart_health_information_log")
        if nv:
            s["media_err"] = nv.get("media_errors", 0)
            s["critico"] = nv.get("critical_warning", 0)
            s["desgaste"] = nv.get("percentage_used")
            self.log(f"   NVMe — desgaste usado: {nv.get('percentage_used', '?')}% · "
                     f"reserva disponible: {nv.get('available_spare', '?')}% · "
                     f"errores de medio: {s['media_err']} · aviso crítico: {s['critico']}",
                     "warn" if (s["media_err"] or s["critico"]) else "info")
        elif not attrs:
            self.log("El dispositivo no expone atributos detallados.", "dim")

        tabla = ((datos.get("ata_smart_self_test_log") or {}).get("standard") or {}).get("table", [])
        fallos = [t for t in tabla if not (t.get("status") or {}).get("passed", True)]
        s["selftest_fallos"] = len(fallos)
        if fallos:
            self.log(f"El historial de autopruebas tiene {len(fallos)} test(s) fallido(s).", "warn")
        self.res["smart"] = s

    def tarea_lectura(self, d):
        dev = d["path"]
        mib = d["size"] // MIB
        if mib < 8:
            self.log("No se detecta capacidad en la unidad (¿sin medio?).", "err")
            return
        n = 128 if mib >= 1024 else max(8, mib // 8)
        zonas = [("inicio", 0.02), ("medio", 0.50), ("final", 0.95)]
        skips = [str(max(0, min(int(mib * f), mib - n))) for _, f in zonas]
        script = ('dev="$1"; n="$2"; shift 2; for s in "$@"; do echo "@@SKIP $s"; '
                  'dd if="$dev" of=/dev/null bs=1M count="$n" skip="$s" iflag=direct 2>&1; done')
        self.prog(None, f"Leyendo {n} MiB en 3 zonas del disco...")
        _, out = self.correr([SH, "-c", script, "sh", dev, str(n), *skips], root=True)
        bloques = out.split("@@SKIP ")[1:]
        vel, io = [], False
        for (nombre, _), b in zip(zonas, bloques):
            v = parse_dd(b)
            if v is None or "rror" in b:
                io = True
                ult = [l for l in b.strip().splitlines() if l.strip()][-1:] or ["sin salida"]
                self.log(f"Zona {nombre}: FALLÓ la lectura — {ult[0].strip()}", "err")
            else:
                vel.append(v)
                self.log(f"Zona {nombre:<6}: {v:7.1f} MB/s", "ok" if v >= 10 else "warn")
        if vel:
            self.log(f"Promedio: {sum(vel) / len(vel):.1f} MB/s · mín {min(vel):.1f} · máx {max(vel):.1f}", "info")
        self.res["lectura"] = {"vel": vel, "io_error": io}

    def tarea_escritura(self, d):
        mp = next((m for m in d["mounts"] if os.access(m, os.W_OK)), None)
        if not mp:
            self.log("No hay partición montada con permiso de escritura; se omite la prueba de escritura.", "warn")
            return
        libre = shutil.disk_usage(mp).free // MIB
        n = int(min(256, libre // 4))
        if n < 16:
            self.log(f"Poco espacio libre en {mp}; se omite la prueba de escritura.", "warn")
            return
        ruta = os.path.join(mp, f".drivesec_{os.getpid()}.tmp")
        w = r = None
        cache = False
        try:
            self.prog(None, f"Escribiendo {n} MiB en {mp}...")
            for flags in (["oflag=direct", "conv=fsync"], ["conv=fdatasync"]):
                rc, out = self.correr(["dd", "if=/dev/zero", f"of={ruta}", "bs=1M", f"count={n}", *flags])
                w = parse_dd(out) if rc == 0 else None
                if w is not None:
                    break
            if w is None:
                self.log("No se pudo completar la escritura de prueba (¿unidad protegida o llena?).", "err")
                return
            self.prog(None, "Leyendo de vuelta el archivo...")
            for flags in (["iflag=direct"], []):
                rc, out = self.correr(["dd", f"if={ruta}", "of=/dev/null", "bs=1M", *flags])
                r = parse_dd(out) if rc == 0 else None
                if r is not None:
                    cache = not flags
                    break
        finally:
            try:
                os.remove(ruta)
            except OSError:
                pass
        self.log(f"Escritura secuencial: {w:.1f} MB/s", "ok" if w >= 5 else "warn")
        if r is not None:
            self.log(f"Lectura del archivo : {r:.1f} MB/s" + (" (posible caché del sistema)" if cache else ""), "info")
        self.res["escritura"] = {"w": w, "r": r}

    def tarea_superficie(self, d):
        dev = d["path"]
        tmp = tempfile.mkdtemp(prefix="drivesec_")
        salida = os.path.join(tmp, "malos.txt")
        carry, t0 = "", time.time()

        def on_text(t):
            nonlocal carry
            carry = (carry + t.replace("\b", ""))[-400:]
            ms = list(RE_BB.finditer(carry))
            if ms:
                g = ms[-1]
                frac = float(g.group(1)) / 100
                eta = f" · ETA {fmt_seg((time.time() - t0) * (1 - frac) / frac)}" if frac > 0.005 else ""
                self.prog(frac, f"Superficie {frac * 100:.2f}%{eta} · errores {g.group(3)}/{g.group(4)}/{g.group(5)}")

        self.log("Escaneo de superficie en modo SOLO LECTURA (badblocks, bloques de 4096 B)...", "info")
        self.prog(0, "Iniciando badblocks...")
        try:
            rc, out = self.correr(["badblocks", "-b", "4096", "-s", "-v", "-o", salida, dev],
                                  root=True, on_text=on_text)
            malos = []
            if os.path.exists(salida):
                with open(salida, encoding="utf-8", errors="replace") as f:
                    malos = [l.strip() for l in f if l.strip().isdigit()]
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        self.log("─" * 50, "dim")
        if rc != 0 and not malos:
            cola = [l for l in out.replace("\b", "").splitlines() if l.strip()][-3:]
            self.log("badblocks terminó con error: " + " | ".join(x.strip() for x in cola), "err")
            return
        if not malos:
            self.log(f"Escaneo completado en {fmt_seg(time.time() - t0)}: 0 bloques ilegibles.", "ok")
            self.log("Nota: en memoria flash esto no garantiza buena salud (el controlador remapea bloques).", "dim")
        else:
            self.log(f"¡{len(malos)} bloque(s) ilegible(s)! No confíes datos importantes a esta unidad.", "err")
            for b in malos[:15]:
                self.log(f"   bloque dañado: {b}", "err")
            if len(malos) > 15:
                self.log(f"   ... y {len(malos) - 15} más", "err")
        self.res["superficie"] = len(malos)

    def tarea_capacidad(self, d):
        dev = d["path"]
        if d["mounts"]:
            self.log("La unidad está montada: desmóntala para probar su capacidad real.", "warn")
            return
        self.log("Probando capacidad real con f3probe (detecta memorias falsificadas)...", "info")
        self.prog(None, "f3probe en curso (puede tardar varios minutos)...")
        _, out = self.correr(["f3probe", "--time-ops", dev], root=True)
        lineas = [l.strip() for l in re.split(r"[\r\n]+", out) if l.strip()][-25:]
        veredicto = None
        for l in lineas:
            low = l.lower()
            if "good news" in low:
                nivel, veredicto = "ok", "ok"
            elif "bad news" in low or "counterfeit" in low or "fake" in low:
                nivel, veredicto = "err", "fake"
            else:
                nivel = "info"
            self.log(l, nivel)
        if veredicto is None:
            self.log("f3probe no dio un veredicto claro (¿dispositivo ocupado o sin permisos?).", "warn")
        else:
            self.res["capacidad"] = veredicto

    def tarea_desmontar(self, d):
        if not d["montadas"]:
            self.log("La unidad ya está desmontada.", "info")
            return
        for dev, mps in d["montadas"]:
            if shutil.which("udisksctl"):
                rc, out = self.correr(["udisksctl", "unmount", "-b", dev])
            else:
                rc, out = 1, "udisksctl no instalado"
                for mp in mps:
                    rc, out = self.correr(["umount", mp], root=True)
            self.log(f"{dev}: " + (out.strip() or "desmontada"), "ok" if rc == 0 else "err")
        self.cola.put(("refrescar",))

    def tarea_completo(self, d, incluir_sup):
        pasos = [("S.M.A.R.T.", self.tarea_smart), ("Velocidad de lectura", self.tarea_lectura)]
        if not d["sistema"]:
            if d["mounts"]:
                pasos.append(("Velocidad de escritura", self.tarea_escritura))
                self.log("Para la prueba de capacidad real desmonta la unidad y ejecútala aparte (paso 5).", "dim")
            elif shutil.which("f3probe"):
                pasos.append(("Capacidad real", self.tarea_capacidad))
            if incluir_sup and shutil.which("badblocks"):
                pasos.append(("Escaneo de superficie", self.tarea_superficie))
        for i, (nombre, fn) in enumerate(pasos, 1):
            self.log(f"── Paso {i}/{len(pasos)}: {nombre} ──", "head")
            try:
                fn(d)
            except (Cancelado, ErrorAuth):
                raise
            except Exception as e:  # noqa: BLE001
                self.log(f"Falló el paso «{nombre}»: {e!r}", "err")
        self.log("Diagnóstico completo terminado.", "head")

    # ───── veredicto y reporte ─────

    def evaluar(self):
        r = self.res
        if not r:
            return None
        riesgos, avisos, hechas = [], [], []

        if "smart" in r:
            s = r["smart"]
            if s is None:
                avisos.append("S.M.A.R.T. no disponible en este dispositivo")
            else:
                hechas.append("S.M.A.R.T.")
                if s.get("passed") is False:
                    riesgos.append("S.M.A.R.T. reporta que la unidad va a fallar")
                if s.get("pendientes", 0) > 0:
                    riesgos.append(f"{s['pendientes']} sectores pendientes/no corregibles")
                if s.get("media_err", 0) > 0:
                    riesgos.append(f"{s['media_err']} errores de medio NVMe")
                if s.get("critico", 0):
                    riesgos.append("aviso crítico del controlador NVMe")
                if s.get("realoc", 0) > 0:
                    avisos.append(f"{s['realoc']} sectores reasignados")
                if (s.get("desgaste") or 0) >= 90:
                    avisos.append(f"desgaste alto ({s['desgaste']}%)")
                if (s.get("temp") or 0) >= 60:
                    avisos.append(f"temperatura alta ({s['temp']} °C)")
                if s.get("selftest_fallos", 0) > 0:
                    avisos.append("autopruebas fallidas en el historial")
                if s.get("crc", 0) > 0:
                    avisos.append("errores CRC (revisa cable/puerto)")

        if "lectura" in r:
            l = r["lectura"]
            hechas.append("lectura")
            if l["io_error"]:
                riesgos.append("errores de lectura en alguna zona")
            if l["vel"]:
                if min(l["vel"]) < 10:
                    avisos.append(f"lectura lenta ({min(l['vel']):.1f} MB/s en la peor zona)")
                if len(l["vel"]) >= 2 and min(l["vel"]) < 0.4 * max(l["vel"]):
                    avisos.append("velocidad muy irregular entre zonas")

        if "escritura" in r:
            hechas.append("escritura")
            if r["escritura"]["w"] < 5:
                avisos.append(f"escritura lenta ({r['escritura']['w']:.1f} MB/s)")

        if "superficie" in r:
            hechas.append("superficie")
            if r["superficie"] > 0:
                riesgos.append(f"{r['superficie']} bloques ilegibles")

        if "capacidad" in r:
            hechas.append("capacidad real")
            if r["capacidad"] == "fake":
                riesgos.append("capacidad falsificada (la memoria no tiene el tamaño anunciado)")

        if riesgos:
            return "riesgo", "RIESGO — " + "; ".join(riesgos + avisos)
        if avisos:
            return "atencion", "ATENCIÓN — " + "; ".join(avisos)
        if not hechas:
            return None
        return "ok", ("SIN HALLAZGOS en las pruebas hechas (" + ", ".join(hechas) +
                      "). Esto no garantiza que la unidad esté sana.")

    def guardar_reporte(self):
        d = self.disco
        base = d["path"].replace("/dev/", "") if d else "general"
        ruta = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Texto", "*.txt")],
            initialfile=f"drivesec_{base}_{datetime.now():%Y%m%d_%H%M}.txt")
        if not ruta:
            return
        cab = ["DRIVE-SEC · REPORTE DE DIAGNÓSTICO", "=" * 40,
               f"Fecha  : {datetime.now():%Y-%m-%d %H:%M:%S}",
               f"Equipo : {socket.gethostname()}", "", info_texto(d), ""]
        if self.ultimo_veredicto:
            cab += [self.ultimo_veredicto, ""]
        try:
            with open(ruta, "w", encoding="utf-8") as f:
                f.write("\n".join(cab) + "\n" + "-" * 40 + "\n" + self.consola.get("1.0", "end"))
            self.log(f"Reporte guardado en {ruta}", "ok")
        except OSError as e:
            self.log(f"No se pudo guardar el reporte: {e}", "err")


if __name__ == "__main__":
    app = DriveSec()
    app.mainloop()
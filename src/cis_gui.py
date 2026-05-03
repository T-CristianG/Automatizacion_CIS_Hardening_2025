"""
cis_gui.py
GUI de CIS Windows Server 2025 Auditor — Level 1
Modos: Auditoría | Hardening
"""

import sys
import os
import threading
import time
import webbrowser
from pathlib import Path

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ---------------------------------------------------------------------------
# Paleta de colores
# ---------------------------------------------------------------------------
C = {
    "bg":        "#0d1117",
    "panel":     "#161b22",
    "card":      "#21262d",
    "border":    "#30363d",
    "text":      "#e6edf3",
    "muted":     "#8b949e",
    "green":     "#3fb950",
    "green_bg":  "#1a3a22",
    "red":       "#f85149",
    "red_bg":    "#3a1a1a",
    "blue":      "#58a6ff",
    "blue_bg":   "#1a2a3a",
    "orange":    "#d29922",
    "purple":    "#bc8cff",
    "yellow":    "#e3b341",
}


# ---------------------------------------------------------------------------
# Clase principal
# ---------------------------------------------------------------------------

class CISAuditorGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("CIS WS 2025 L1 — Audit & Hardening")
        self.root.geometry("1100x750")
        self.root.configure(bg=C["bg"])
        self.root.resizable(True, True)
        self.root.minsize(900, 600)

        # Estado
        self.audit_results: list[dict] = []
        self.all_rules: list = []
        self.hardening_vars: dict = {}   # cis_id → BooleanVar
        self.hardening_rule_map: dict = {}  # cis_id → Rule object
        self.is_running = False
        self.report_path = Path.cwd() / "CIS_WS2025_L1_Report.html"

        # Frames de "pantalla"
        self.screens: dict[str, tk.Frame] = {}

        self._build_header()
        self._build_screens()
        self._show_screen("home")
        self._center_window()

        # Cargar reglas en background para no bloquear la UI
        threading.Thread(target=self._load_rules, daemon=True).start()

    # -----------------------------------------------------------------------
    # Construcción de la UI
    # -----------------------------------------------------------------------

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=C["panel"], height=64)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="🛡️", font=("Segoe UI Emoji", 26),
                 bg=C["panel"], fg=C["blue"]).pack(side="left", padx=(18, 8), pady=10)

        tf = tk.Frame(hdr, bg=C["panel"])
        tf.pack(side="left", pady=10)
        tk.Label(tf, text="CIS Windows Server 2025  ·  Level 1",
                 font=("Segoe UI", 14, "bold"), bg=C["panel"], fg=C["text"]).pack(anchor="w")
        tk.Label(tf, text="Member Server  |  Automated Audit & Hardening",
                 font=("Segoe UI", 9), bg=C["panel"], fg=C["muted"]).pack(anchor="w")

        # Botones de navegación en el header
        nav_frame = tk.Frame(hdr, bg=C["panel"])
        nav_frame.pack(side="right", padx=18)

        self.nav_audit_btn = tk.Button(
            nav_frame, text="🔍  Auditoría",
            font=("Segoe UI", 10, "bold"),
            bg=C["card"], fg=C["text"],
            activebackground=C["blue_bg"], activeforeground=C["blue"],
            relief="flat", padx=14, pady=6, cursor="hand2",
            command=lambda: self._show_screen("audit")
        )
        self.nav_audit_btn.pack(side="left", padx=(0, 8))

        self.nav_harden_btn = tk.Button(
            nav_frame, text="🔒  Hardening",
            font=("Segoe UI", 10, "bold"),
            bg=C["card"], fg=C["text"],
            activebackground=C["green_bg"], activeforeground=C["green"],
            relief="flat", padx=14, pady=6, cursor="hand2",
            command=lambda: self._show_screen("hardening")
        )
        self.nav_harden_btn.pack(side="left")

        # Separador
        tk.Frame(self.root, bg=C["border"], height=1).pack(fill="x")

    def _build_screens(self):
        container = tk.Frame(self.root, bg=C["bg"])
        container.pack(fill="both", expand=True)
        self._container = container

        self.screens["home"]      = self._build_home_screen(container)
        self.screens["audit"]     = self._build_audit_screen(container)
        self.screens["hardening"] = self._build_hardening_screen(container)

    # ----- HOME -----
    def _build_home_screen(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])

        # Título central
        tk.Label(frame, text="🛡️",
                 font=("Segoe UI Emoji", 60),
                 bg=C["bg"], fg=C["blue"]).pack(pady=(60, 10))

        tk.Label(frame,
                 text="CIS Benchmark Automation",
                 font=("Segoe UI", 24, "bold"),
                 bg=C["bg"], fg=C["text"]).pack()

        tk.Label(frame,
                 text="Windows Server 2025  ·  Level 1  ·  Member Server",
                 font=("Segoe UI", 12),
                 bg=C["bg"], fg=C["muted"]).pack(pady=(4, 40))

        # Dos tarjetas de modo
        cards_frame = tk.Frame(frame, bg=C["bg"])
        cards_frame.pack()

        self._mode_card(
            cards_frame,
            icon="🔍",
            title="Auditoría",
            desc="Evalúa el cumplimiento de los\ncontroles CIS Level 1 y genera\nun reporte HTML detallado.",
            btn_text="Iniciar Auditoría",
            btn_color=C["blue"],
            btn_bg=C["blue_bg"],
            command=lambda: self._show_screen("audit"),
        ).pack(side="left", padx=20)

        self._mode_card(
            cards_frame,
            icon="🔒",
            title="Hardening",
            desc="Aplica automáticamente los\ncontroles fallidos para poner\nel servidor en cumplimiento.",
            btn_text="Aplicar Hardening",
            btn_color=C["green"],
            btn_bg=C["green_bg"],
            command=lambda: self._show_screen("hardening"),
        ).pack(side="left", padx=20)

        # Nota admin
        tk.Label(frame,
                 text="⚠  Este programa debe ejecutarse como Administrador",
                 font=("Segoe UI", 9),
                 bg=C["bg"], fg=C["orange"]).pack(pady=(40, 0))

        return frame

    def _mode_card(self, parent, icon, title, desc, btn_text, btn_color, btn_bg, command):
        card = tk.Frame(parent, bg=C["card"], relief="flat",
                        highlightbackground=C["border"], highlightthickness=1)

        tk.Label(card, text=icon, font=("Segoe UI Emoji", 40),
                 bg=C["card"], fg=btn_color).pack(pady=(28, 4))

        tk.Label(card, text=title, font=("Segoe UI", 16, "bold"),
                 bg=C["card"], fg=C["text"]).pack()

        tk.Label(card, text=desc, font=("Segoe UI", 10),
                 bg=C["card"], fg=C["muted"], justify="center").pack(pady=(8, 20))

        tk.Button(
            card, text=btn_text,
            font=("Segoe UI", 11, "bold"),
            bg=btn_color, fg=C["bg"],
            activebackground=btn_bg, activeforeground=btn_color,
            relief="flat", padx=20, pady=10, cursor="hand2",
            command=command
        ).pack(pady=(0, 28))

        return card

    # ----- AUDIT -----
    def _build_audit_screen(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])

        # Título
        hf = tk.Frame(frame, bg=C["bg"])
        hf.pack(fill="x", padx=20, pady=(16, 0))
        tk.Label(hf, text="🔍  Auditoría CIS Level 1",
                 font=("Segoe UI", 14, "bold"),
                 bg=C["bg"], fg=C["text"]).pack(side="left")

        self.open_report_btn = tk.Button(
            hf, text="📊 Abrir Reporte HTML",
            font=("Segoe UI", 9),
            bg=C["card"], fg=C["blue"],
            activebackground=C["blue_bg"], activeforeground=C["blue"],
            relief="flat", padx=10, pady=4, cursor="hand2",
            state="disabled",
            command=self._open_report
        )
        self.open_report_btn.pack(side="right")

        # Cards de resumen
        self.audit_summary_frame = tk.Frame(frame, bg=C["bg"])
        self.audit_summary_frame.pack(fill="x", padx=20, pady=10)
        self._build_summary_cards()

        # Progreso
        prog_frame = tk.Frame(frame, bg=C["panel"],
                              highlightbackground=C["border"], highlightthickness=1)
        prog_frame.pack(fill="x", padx=20, pady=(0, 10))

        self.audit_status_label = tk.Label(
            prog_frame, text="Listo para iniciar la auditoría.",
            font=("Segoe UI", 9), bg=C["panel"], fg=C["muted"], anchor="w"
        )
        self.audit_status_label.pack(fill="x", padx=12, pady=(8, 4))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Audit.Horizontal.TProgressbar",
                        background=C["blue"], troughcolor=C["card"],
                        bordercolor=C["panel"])
        self.audit_progress = ttk.Progressbar(
            prog_frame, style="Audit.Horizontal.TProgressbar",
            orient="horizontal", mode="determinate"
        )
        self.audit_progress.pack(fill="x", padx=12, pady=(0, 8))

        # Consola
        console_lf = tk.LabelFrame(frame, text=" Salida en tiempo real ",
                                   font=("Segoe UI", 9, "bold"),
                                   fg=C["muted"], bg=C["bg"],
                                   highlightbackground=C["border"],
                                   relief="flat", borderwidth=1)
        console_lf.pack(fill="both", expand=True, padx=20, pady=(0, 8))

        self.audit_console = scrolledtext.ScrolledText(
            console_lf, height=14,
            font=("Consolas", 9),
            bg=C["panel"], fg=C["text"],
            insertbackground=C["text"], wrap="word",
            relief="flat"
        )
        self.audit_console.pack(fill="both", expand=True, padx=4, pady=4)
        self._setup_console_tags(self.audit_console)

        # Botón Run
        btn_row = tk.Frame(frame, bg=C["bg"])
        btn_row.pack(fill="x", padx=20, pady=(0, 12))

        self.run_audit_btn = tk.Button(
            btn_row,
            text="▶  EJECUTAR AUDITORÍA",
            font=("Segoe UI", 12, "bold"),
            bg=C["blue"], fg=C["bg"],
            activebackground=C["blue_bg"], activeforeground=C["blue"],
            relief="flat", padx=30, pady=12, cursor="hand2",
            command=self._start_audit
        )
        self.run_audit_btn.pack(side="left")

        self.audit_to_hardening_btn = tk.Button(
            btn_row,
            text="🔒 Ver Hardening de Fallos",
            font=("Segoe UI", 10),
            bg=C["card"], fg=C["green"],
            activebackground=C["green_bg"], activeforeground=C["green"],
            relief="flat", padx=14, pady=12, cursor="hand2",
            state="disabled",
            command=self._go_to_hardening_with_failures
        )
        self.audit_to_hardening_btn.pack(side="left", padx=(12, 0))

        return frame

    def _build_summary_cards(self):
        for w in self.audit_summary_frame.winfo_children():
            w.destroy()

        data = [
            ("Total",    "—", C["muted"],  C["card"]),
            ("✅ Passed", "—", C["green"],  C["green_bg"]),
            ("❌ Failed", "—", C["red"],    C["red_bg"]),
            ("% Cumpl.",  "—", C["blue"],   C["blue_bg"]),
        ]

        if self.audit_results:
            total  = len(self.audit_results)
            passed = sum(1 for r in self.audit_results if r["pass"])
            failed = total - passed
            pct    = f"{passed/total*100:.1f}%" if total else "0%"
            data = [
                ("Total",    str(total),  C["muted"],  C["card"]),
                ("✅ Passed", str(passed), C["green"],  C["green_bg"]),
                ("❌ Failed", str(failed), C["red"],    C["red_bg"]),
                ("% Cumpl.",  pct,         C["blue"],   C["blue_bg"]),
            ]

        for label, value, fg, bg in data:
            card = tk.Frame(self.audit_summary_frame, bg=bg,
                            highlightbackground=C["border"], highlightthickness=1)
            card.pack(side="left", padx=(0, 10), ipadx=16, ipady=8)
            tk.Label(card, text=value, font=("Segoe UI", 22, "bold"),
                     bg=bg, fg=fg).pack()
            tk.Label(card, text=label, font=("Segoe UI", 9),
                     bg=bg, fg=C["muted"]).pack()

    # ----- HARDENING -----
    def _build_hardening_screen(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])

        # Título
        hf = tk.Frame(frame, bg=C["bg"])
        hf.pack(fill="x", padx=20, pady=(16, 0))
        tk.Label(hf, text="🔒  Hardening  —  Aplicar controles CIS",
                 font=("Segoe UI", 14, "bold"),
                 bg=C["bg"], fg=C["text"]).pack(side="left")

        # Botones de selección masiva
        sel_frame = tk.Frame(frame, bg=C["bg"])
        sel_frame.pack(fill="x", padx=20, pady=8)

        tk.Button(sel_frame, text="☑ Seleccionar todos los FAIL",
                  font=("Segoe UI", 9), bg=C["card"], fg=C["red"],
                  activebackground=C["red_bg"], activeforeground=C["red"],
                  relief="flat", padx=10, pady=4, cursor="hand2",
                  command=self._select_all_failed).pack(side="left", padx=(0, 6))

        tk.Button(sel_frame, text="☑ Seleccionar todos",
                  font=("Segoe UI", 9), bg=C["card"], fg=C["muted"],
                  relief="flat", padx=10, pady=4, cursor="hand2",
                  command=self._select_all).pack(side="left", padx=(0, 6))

        tk.Button(sel_frame, text="☐ Deseleccionar todos",
                  font=("Segoe UI", 9), bg=C["card"], fg=C["muted"],
                  relief="flat", padx=10, pady=4, cursor="hand2",
                  command=self._deselect_all).pack(side="left")

        # Filtro de texto
        filter_frame = tk.Frame(sel_frame, bg=C["bg"])
        filter_frame.pack(side="right")
        tk.Label(filter_frame, text="🔍", bg=C["bg"], fg=C["muted"],
                 font=("Segoe UI Emoji", 11)).pack(side="left")
        self.harden_filter_var = tk.StringVar()
        self.harden_filter_var.trace_add("write", self._filter_hardening_list)
        tk.Entry(filter_frame, textvariable=self.harden_filter_var,
                 font=("Segoe UI", 9), bg=C["card"], fg=C["text"],
                 insertbackground=C["text"], relief="flat",
                 width=28).pack(side="left", padx=4)

        # Lista scrollable de controles
        list_outer = tk.Frame(frame, bg=C["panel"],
                              highlightbackground=C["border"], highlightthickness=1)
        list_outer.pack(fill="both", expand=True, padx=20, pady=(0, 8))

        # Canvas + Scrollbar para la lista
        self.harden_canvas = tk.Canvas(list_outer, bg=C["panel"],
                                       highlightthickness=0)
        vsb = ttk.Scrollbar(list_outer, orient="vertical",
                            command=self.harden_canvas.yview)
        self.harden_canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.harden_canvas.pack(side="left", fill="both", expand=True)

        self.harden_list_frame = tk.Frame(self.harden_canvas, bg=C["panel"])
        self._canvas_window = self.harden_canvas.create_window(
            (0, 0), window=self.harden_list_frame, anchor="nw"
        )
        self.harden_list_frame.bind(
            "<Configure>",
            lambda e: self.harden_canvas.configure(
                scrollregion=self.harden_canvas.bbox("all")
            )
        )
        self.harden_canvas.bind(
            "<Configure>",
            lambda e: self.harden_canvas.itemconfig(
                self._canvas_window, width=e.width
            )
        )
        # Scroll con rueda del ratón
        self.harden_canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Placeholder mensaje
        self.harden_placeholder = tk.Label(
            self.harden_list_frame,
            text="Ejecuta primero la Auditoría para ver los controles disponibles.\n\n"
                 "Ve a la pestaña 🔍 Auditoría y haz clic en EJECUTAR AUDITORÍA.",
            font=("Segoe UI", 11), bg=C["panel"], fg=C["muted"],
            justify="center"
        )
        self.harden_placeholder.pack(pady=60)

        # Barra de progreso hardening
        prog_frame = tk.Frame(frame, bg=C["panel"],
                              highlightbackground=C["border"], highlightthickness=1)
        prog_frame.pack(fill="x", padx=20, pady=(0, 6))

        self.harden_status_label = tk.Label(
            prog_frame, text="Selecciona controles y haz clic en APLICAR HARDENING.",
            font=("Segoe UI", 9), bg=C["panel"], fg=C["muted"], anchor="w"
        )
        self.harden_status_label.pack(fill="x", padx=12, pady=(8, 4))

        style = ttk.Style()
        style.configure("Harden.Horizontal.TProgressbar",
                        background=C["green"], troughcolor=C["card"],
                        bordercolor=C["panel"])
        self.harden_progress = ttk.Progressbar(
            prog_frame, style="Harden.Horizontal.TProgressbar",
            orient="horizontal", mode="determinate"
        )
        self.harden_progress.pack(fill="x", padx=12, pady=(0, 8))

        # Consola de hardening
        hcons_lf = tk.LabelFrame(frame, text=" Log de aplicación ",
                                 font=("Segoe UI", 9, "bold"),
                                 fg=C["muted"], bg=C["bg"],
                                 relief="flat", borderwidth=1)
        hcons_lf.pack(fill="x", padx=20, pady=(0, 6))

        self.harden_console = scrolledtext.ScrolledText(
            hcons_lf, height=7,
            font=("Consolas", 9),
            bg=C["panel"], fg=C["text"],
            insertbackground=C["text"], wrap="word",
            relief="flat"
        )
        self.harden_console.pack(fill="x", expand=False, padx=4, pady=4)
        self._setup_console_tags(self.harden_console)

        # Botón aplicar hardening
        btn_row = tk.Frame(frame, bg=C["bg"])
        btn_row.pack(fill="x", padx=20, pady=(0, 12))

        self.apply_harden_btn = tk.Button(
            btn_row,
            text="⚡  APLICAR HARDENING",
            font=("Segoe UI", 12, "bold"),
            bg=C["green"], fg=C["bg"],
            activebackground=C["green_bg"], activeforeground=C["green"],
            relief="flat", padx=30, pady=12, cursor="hand2",
            command=self._start_hardening
        )
        self.apply_harden_btn.pack(side="left")

        self.harden_selected_label = tk.Label(
            btn_row, text="0 controles seleccionados",
            font=("Segoe UI", 9), bg=C["bg"], fg=C["muted"]
        )
        self.harden_selected_label.pack(side="left", padx=14)

        return frame

    # -----------------------------------------------------------------------
    # Helpers de UI
    # -----------------------------------------------------------------------

    def _setup_console_tags(self, widget):
        widget.tag_config("ok",      foreground=C["green"])
        widget.tag_config("fail",    foreground=C["red"])
        widget.tag_config("warn",    foreground=C["orange"])
        widget.tag_config("info",    foreground=C["blue"])
        widget.tag_config("step",    foreground=C["purple"])
        widget.tag_config("muted",   foreground=C["muted"])

    def _log(self, widget, msg: str, tag: str = ""):
        widget.insert(tk.END, msg + "\n", tag)
        widget.see(tk.END)
        self.root.update_idletasks()

    def _show_screen(self, name: str):
        for f in self.screens.values():
            f.pack_forget()
        self.screens[name].pack(fill="both", expand=True)

        # Resaltar botón activo en header
        self.nav_audit_btn.config(
            fg=C["blue"] if name == "audit" else C["text"],
            bg=C["blue_bg"] if name == "audit" else C["card"]
        )
        self.nav_harden_btn.config(
            fg=C["green"] if name == "hardening" else C["text"],
            bg=C["green_bg"] if name == "hardening" else C["card"]
        )

    def _center_window(self):
        self.root.update_idletasks()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        x = (self.root.winfo_screenwidth()  - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _on_mousewheel(self, event):
        try:
            self.harden_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Carga de reglas
    # -----------------------------------------------------------------------

    def _load_rules(self):
        try:
            from checks.all_checks import rules
            self.all_rules = rules
            self.root.after(0, lambda: self._log(
                self.audit_console,
                f"✅ {len(rules)} reglas CIS cargadas correctamente.",
                "ok"
            ))
        except Exception as e:
            self.root.after(0, lambda: self._log(
                self.audit_console,
                f"❌ Error cargando reglas: {e}",
                "fail"
            ))

    # -----------------------------------------------------------------------
    # AUDITORÍA
    # -----------------------------------------------------------------------

    def _start_audit(self):
        if self.is_running:
            return
        if not self.all_rules:
            messagebox.showerror("Error", "Las reglas no están cargadas todavía. Espera un momento.")
            return

        self.is_running = True
        self.audit_results = []
        self.audit_console.delete(1.0, tk.END)
        self.audit_progress["value"] = 0
        self.run_audit_btn.config(state="disabled", text="⏳ Ejecutando…")
        self.audit_to_hardening_btn.config(state="disabled")
        self.open_report_btn.config(state="disabled")

        threading.Thread(target=self._audit_worker, daemon=True).start()

    def _audit_worker(self):
        try:
            from core.helpers import is_admin
            if not is_admin():
                self.root.after(0, lambda: messagebox.showerror(
                    "Sin privilegios",
                    "Este programa debe ejecutarse como Administrador.\n"
                    "Ciérralo y ábrelo con 'Ejecutar como administrador'."
                ))
                return

            rules = self.all_rules
            total = len(rules)
            results = []

            self.root.after(0, lambda: self._log(
                self.audit_console,
                f"▶ Iniciando auditoría de {total} controles CIS Level 1…",
                "step"
            ))

            for i, rule in enumerate(rules, 1):
                self.root.after(0, lambda r=rule, n=i, t=total: (
                    self.audit_status_label.config(
                        text=f"[{n}/{t}] Verificando {r.cis_id}…"
                    )
                ))

                result = rule.evaluate()
                results.append(result)

                pct = int(i / total * 100)
                tag = "ok" if result["pass"] else "fail"
                icon = "✅" if result["pass"] else "❌"

                self.root.after(0, lambda r=result, tg=tag, ic=icon, p=pct: (
                    self._log(self.audit_console,
                              f"{ic} [{r['cis_id']}] {r['title'][:70]}", tg),
                    self.audit_progress.__setitem__("value", p)
                ))

            self.audit_results = results

            # Generar reporte
            self.root.after(0, lambda: self._log(
                self.audit_console, "\n📄 Generando reporte HTML…", "info"
            ))

            from reports.html_reporter import render_html
            html = render_html(results)
            self.report_path.write_text(html, encoding="utf-8")

            passed = sum(1 for r in results if r["pass"])
            failed = total - passed
            pct    = passed / total * 100 if total else 0.0

            self.root.after(0, lambda: (
                self._log(self.audit_console,
                          f"\n{'='*60}", "muted"),
                self._log(self.audit_console,
                          f"✅ Auditoría completada: {passed}/{total} controles pasados ({pct:.1f}%)", "ok"),
                self._log(self.audit_console,
                          f"❌ Controles fallidos: {failed}", "fail"),
                self._log(self.audit_console,
                          f"📄 Reporte guardado: {self.report_path}", "info"),
                self._build_summary_cards(),
                self.open_report_btn.config(state="normal"),
                self.audit_to_hardening_btn.config(state="normal"),
                self.audit_status_label.config(
                    text=f"Completado: {passed}/{total} ({pct:.1f}%)"
                ),
                self._populate_hardening_list(results)
            ))

        except Exception as e:
            self.root.after(0, lambda: self._log(
                self.audit_console, f"\n❌ Error durante auditoría: {e}", "fail"
            ))
        finally:
            self.is_running = False
            self.root.after(0, lambda: self.run_audit_btn.config(
                state="normal", text="▶  EJECUTAR AUDITORÍA"
            ))

    def _open_report(self):
        if self.report_path.exists():
            webbrowser.open(f"file:///{self.report_path}")
        else:
            messagebox.showwarning("Sin reporte", "El reporte aún no se ha generado.")

    # -----------------------------------------------------------------------
    # HARDENING — Lista de controles
    # -----------------------------------------------------------------------

    def _populate_hardening_list(self, results: list[dict]):
        """Llena la lista de controles en la pantalla de hardening."""
        # Limpiar
        for w in self.harden_list_frame.winfo_children():
            w.destroy()

        if self.harden_placeholder:
            self.harden_placeholder = None

        self.hardening_vars = {}
        self.hardening_rule_map = {}

        # Construir mapa cis_id → rule
        for rule in self.all_rules:
            self.hardening_rule_map[rule.cis_id] = rule

        # Encabezado de columnas
        hdr = tk.Frame(self.harden_list_frame, bg=C["card"])
        hdr.pack(fill="x", padx=2, pady=(2, 0))

        for text, width, anchor in [
            ("", 30, "center"),
            ("CIS ID", 90, "w"),
            ("Estado", 60, "center"),
            ("Recomendación", 0, "w"),
        ]:
            tk.Label(hdr, text=text, width=width if width else None,
                     font=("Segoe UI", 8, "bold"),
                     bg=C["card"], fg=C["muted"],
                     anchor=anchor).pack(side="left", padx=4, pady=4)

        tk.Frame(self.harden_list_frame, bg=C["border"], height=1).pack(fill="x")

        # Filas
        for result in results:
            cis_id = result["cis_id"]
            passed = result["pass"]
            title  = result["title"]
            rule   = self.hardening_rule_map.get(cis_id)
            has_rem = rule is not None and rule.remediate_fn is not None

            var = tk.BooleanVar(value=not passed)  # Preseleccionar los fallidos
            self.hardening_vars[cis_id] = var

            row = tk.Frame(self.harden_list_frame, bg=C["panel"], cursor="hand2")
            row.pack(fill="x", padx=2)
            row.bind("<Button-1>", lambda e, v=var: v.set(not v.get()))

            # Checkbox
            cb = tk.Checkbutton(
                row, variable=var,
                bg=C["panel"], activebackground=C["panel"],
                fg=C["text"], selectcolor=C["card"],
                relief="flat"
            )
            cb.pack(side="left", padx=(6, 2))

            # CIS ID
            tk.Label(row, text=cis_id, width=10,
                     font=("Consolas", 9, "bold"),
                     bg=C["panel"], fg=C["blue"], anchor="w"
                     ).pack(side="left", padx=4)

            # Status pill
            s_text = "PASS" if passed else "FAIL"
            s_fg   = C["green"] if passed else C["red"]
            s_bg   = C["green_bg"] if passed else C["red_bg"]
            tk.Label(row, text=s_text, width=6,
                     font=("Segoe UI", 8, "bold"),
                     bg=s_bg, fg=s_fg, anchor="center"
                     ).pack(side="left", padx=4)

            # Título (truncado)
            rem_icon = "" if has_rem else " 🔧✗"
            tk.Label(row, text=title[:95] + rem_icon,
                     font=("Segoe UI", 9),
                     bg=C["panel"], fg=C["text"] if has_rem else C["muted"],
                     anchor="w"
                     ).pack(side="left", padx=4, fill="x", expand=True)

            # Separador
            tk.Frame(self.harden_list_frame, bg=C["border"], height=1).pack(fill="x", padx=2)

        self._update_selected_count()
        # Observar cambios en vars para actualizar contador
        for var in self.hardening_vars.values():
            var.trace_add("write", lambda *_: self._update_selected_count())

    def _update_selected_count(self):
        count = sum(1 for v in self.hardening_vars.values() if v.get())
        self.harden_selected_label.config(
            text=f"{count} controles seleccionados"
        )

    def _filter_hardening_list(self, *_):
        q = self.harden_filter_var.get().strip().lower()
        for widget in self.harden_list_frame.winfo_children():
            if not isinstance(widget, tk.Frame):
                continue
            text = widget.winfo_children()
            # Obtener texto de todos los labels en la fila
            row_text = " ".join(
                str(child.cget("text"))
                for child in widget.winfo_children()
                if isinstance(child, tk.Label)
            ).lower()
            widget.pack_configure(
                pady=0
            )
            if q and q not in row_text:
                widget.pack_forget()
            else:
                widget.pack(fill="x", padx=2)

    def _select_all_failed(self):
        for cis_id, var in self.hardening_vars.items():
            # Buscar en results si falló
            for r in self.audit_results:
                if r["cis_id"] == cis_id:
                    var.set(not r["pass"])
                    break

    def _select_all(self):
        for var in self.hardening_vars.values():
            var.set(True)

    def _deselect_all(self):
        for var in self.hardening_vars.values():
            var.set(False)

    def _go_to_hardening_with_failures(self):
        self._show_screen("hardening")

    # -----------------------------------------------------------------------
    # HARDENING — Ejecución
    # -----------------------------------------------------------------------

    def _start_hardening(self):
        if self.is_running:
            return

        # Seleccionar reglas marcadas que tengan remediación
        selected = []
        for cis_id, var in self.hardening_vars.items():
            if var.get():
                rule = self.hardening_rule_map.get(cis_id)
                if rule:
                    selected.append(rule)

        if not selected:
            messagebox.showinfo("Sin selección",
                                "No hay controles seleccionados.\n"
                                "Marca las casillas de los controles que deseas aplicar.")
            return

        # Filtrar los que tienen remediación
        automatable = [r for r in selected if r.remediate_fn is not None]
        manual_count = len(selected) - len(automatable)

        if not automatable:
            messagebox.showwarning("Sin remediación",
                                   "Los controles seleccionados no tienen remediación automatizada.")
            return

        msg = f"Se aplicarán {len(automatable)} controles automáticamente."
        if manual_count:
            msg += f"\n{manual_count} control(es) no tienen remediación automática y serán omitidos."
        msg += "\n\n⚠  Esta operación modifica la configuración del servidor.\n¿Continuar?"

        if not messagebox.askyesno("Confirmar Hardening", msg, icon="warning"):
            return

        self.is_running = True
        self.harden_console.delete(1.0, tk.END)
        self.harden_progress["value"] = 0
        self.apply_harden_btn.config(state="disabled", text="⏳ Aplicando…")

        threading.Thread(
            target=self._hardening_worker,
            args=(automatable,),
            daemon=True
        ).start()

    def _hardening_worker(self, rules_to_apply: list):
        total   = len(rules_to_apply)
        success = 0
        failed  = 0

        self.root.after(0, lambda: self._log(
            self.harden_console,
            f"▶ Aplicando {total} controles de hardening CIS Level 1…",
            "step"
        ))

        for i, rule in enumerate(rules_to_apply, 1):
            self.root.after(0, lambda r=rule, n=i, t=total: (
                self.harden_status_label.config(
                    text=f"[{n}/{t}] Aplicando {r.cis_id}…"
                )
            ))

            result = rule.remediate()
            pct = int(i / total * 100)

            if result["success"]:
                success += 1
                tag, icon = "ok", "✅"
            else:
                failed += 1
                tag, icon = "fail", "❌"

            self.root.after(0, lambda r=result, tg=tag, ic=icon, p=pct: (
                self._log(
                    self.harden_console,
                    f"{ic} [{r['cis_id']}] {r['message'][:80]}",
                    tg
                ),
                self.harden_progress.__setitem__("value", p)
            ))

        self.root.after(0, lambda: (
            self._log(self.harden_console, f"\n{'='*60}", "muted"),
            self._log(self.harden_console,
                      f"✅ Hardening completado: {success}/{total} aplicados correctamente",
                      "ok"),
            self._log(self.harden_console,
                      f"❌ Con errores: {failed}",
                      "fail" if failed else "muted"),
            self._log(self.harden_console,
                      "ℹ  Ejecuta la Auditoría nuevamente para verificar los cambios.",
                      "info"),
            self.harden_status_label.config(
                text=f"Completado: {success}/{total} aplicados | {failed} con error"
            )
        ))

        self.is_running = False
        self.root.after(0, lambda: self.apply_harden_btn.config(
            state="normal", text="⚡  APLICAR HARDENING"
        ))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    root = tk.Tk()
    app  = CISAuditorGUI(root)

    def on_close():
        if app.is_running:
            if not messagebox.askokcancel(
                "Operación en curso",
                "Hay una operación en curso.\n¿Deseas salir de todas formas?"
            ):
                return
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()

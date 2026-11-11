from __future__ import annotations

import json
import os
import queue
import sys
import threading
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

HERE = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent
)
sys.path.insert(0, str(HERE))

import build_ips_windows as builder
import class_c_elements as cce
import xlsx_export

APP_TITLE = "Luminator MTU to IPS Converter"
SETTINGS_DIR = Path(os.environ.get("APPDATA", Path.home())) / "LuminatorMTUtoIPS"
SETTINGS_FILE = SETTINGS_DIR / "settings.json"


def _default_donor() -> str:
    """The bundled Donor.ips, else one the user located earlier."""
    bundled = builder.bundled_donor()
    if bundled is not None:
        return str(bundled)
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        donor = Path(data.get("donor", ""))
        if donor.is_file():
            return str(donor)
    except Exception:
        pass
    return ""


class ConverterUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x760")
        self.minsize(820, 620)
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.worker = None

        self.mtu_var = tk.StringVar()
        self.out_var = tk.StringVar()
        self.donor_var = tk.StringVar(value=_default_donor())
        self.name_var = tk.StringVar(value="RECOVERED")
        self._auto_output = ""
        self._auto_name = "RECOVERED"
        self.element_vars = {name: tk.BooleanVar(value=name in ("RouteFront", "MainFront"))
                             for name in cce.ELEMENTS}
        self.custom_layout: cce.CustomLayout | None = None
        self.custom_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Select an MTU file to begin.")
        self.open_folder_var = tk.BooleanVar(value=True)
        self.best_effort_var = tk.BooleanVar(value=False)
        self.progress_var = tk.DoubleVar(value=0)

        self._configure_style()
        self._build_ui()
        self.after(100, self._pump_events)

    def _configure_style(self):
        self.configure(background="#0B1220")
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Converter.TEntry",
            fieldbackground="#0F172A",
            foreground="#F8FAFC",
            bordercolor="#334155",
            lightcolor="#334155",
            darkcolor="#334155",
            insertcolor="#F8FAFC",
            padding=(10, 8),
        )
        style.map("Converter.TEntry", bordercolor=[("focus", "#3B82F6")])
        style.configure(
            "Converter.TCombobox",
            fieldbackground="#0F172A",
            background="#172033",
            foreground="#F8FAFC",
            arrowcolor="#CBD5E1",
            bordercolor="#334155",
            insertcolor="#F8FAFC",
            padding=(8, 6),
        )
        style.map(
            "Converter.TCombobox",
            fieldbackground=[("readonly", "#0F172A")],
            selectbackground=[("readonly", "#0F172A")],
            selectforeground=[("readonly", "#F8FAFC")],
            bordercolor=[("focus", "#3B82F6")],
        )
        style.configure(
            "Converter.TButton",
            background="#172033",
            foreground="#F8FAFC",
            bordercolor="#334155",
            padding=(12, 8),
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "Converter.TButton",
            background=[("active", "#22304A"), ("disabled", "#111827")],
            foreground=[("disabled", "#64748B")],
        )
        style.configure(
            "Primary.Converter.TButton",
            background="#2563EB",
            foreground="#FFFFFF",
            bordercolor="#3B82F6",
        )
        style.map(
            "Primary.Converter.TButton",
            background=[("active", "#1D4ED8"), ("disabled", "#1E3A5F")],
            foreground=[("disabled", "#93C5FD")],
        )
        style.configure(
            "Converter.TCheckbutton",
            background="#111827",
            foreground="#CBD5E1",
            font=("Segoe UI", 9),
        )
        style.map(
            "Converter.TCheckbutton",
            background=[("active", "#111827")],
            foreground=[("disabled", "#64748B")],
        )
        style.configure(
            "Converter.Horizontal.TProgressbar",
            background="#3B82F6",
            troughcolor="#172033",
            bordercolor="#253047",
            lightcolor="#3B82F6",
            darkcolor="#3B82F6",
            thickness=8,
        )

    def _build_ui(self):
        root = tk.Frame(self, bg="#0B1220", padx=20, pady=18)
        root.pack(fill="both", expand=True)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(3, weight=1)

        header = tk.Frame(root, bg="#0B1220")
        header.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 16))
        tk.Label(
            header,
            text=APP_TITLE,
            bg="#0B1220",
            fg="#F8FAFC",
            font=("Segoe UI", 18, "bold"),
        ).grid(row=0, column=0, sticky="w")

        inputs = tk.Frame(
            root,
            bg="#111827",
            highlightbackground="#253047",
            highlightthickness=1,
            padx=18,
            pady=16,
        )
        inputs.grid(row=1, column=0, columnspan=3, sticky="ew")
        inputs.columnconfigure(1, weight=1)
        tk.Label(
            inputs,
            text="Project Inputs",
            bg="#111827",
            fg="#F8FAFC",
            font=("Segoe UI", 11, "bold"),
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))

        label_options = {"bg": "#111827", "fg": "#CBD5E1", "font": ("Segoe UI", 9)}
        tk.Label(inputs, text="Input MTU", **label_options).grid(row=1, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(inputs, textvariable=self.mtu_var, style="Converter.TEntry").grid(row=1, column=1, sticky="ew", pady=5)
        ttk.Button(inputs, text="Browse", style="Converter.TButton", command=self._browse_mtu).grid(row=1, column=2, padx=(10, 0), pady=5)

        tk.Label(inputs, text="Output IPS", **label_options).grid(row=2, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(inputs, textvariable=self.out_var, style="Converter.TEntry").grid(row=2, column=1, sticky="ew", pady=5)
        ttk.Button(inputs, text="Save As", style="Converter.TButton", command=self._browse_output).grid(row=2, column=2, padx=(10, 0), pady=5)


        tk.Label(inputs, text="Project Name", **label_options).grid(row=4, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(inputs, textvariable=self.name_var, style="Converter.TEntry").grid(row=4, column=1, sticky="ew", pady=5)
        tk.Label(inputs, text="20 characters max", bg="#111827", fg="#94A3B8", font=("Segoe UI", 8)).grid(row=4, column=2, sticky="e", padx=(10, 0), pady=5)

        tk.Label(inputs, text="Class C Elements", **label_options).grid(row=5, column=0, sticky="nw", padx=(0, 12), pady=5)
        elements_box = tk.Frame(inputs, bg="#111827")
        elements_box.grid(row=5, column=1, sticky="ew", pady=5)
        self.element_checks = {}
        for index, name in enumerate(cce.ELEMENTS):
            check = ttk.Checkbutton(
                elements_box, text=name, variable=self.element_vars[name], style="Converter.TCheckbutton")
            check.grid(row=index // 3, column=index % 3, sticky="w", padx=(0, 18), pady=1)
            if name in cce.REQUIRED_ELEMENTS:
                self.element_vars[name].set(True)
                check.state(["disabled"])
            self.element_checks[name] = check
        self.suggest_btn = ttk.Button(inputs, text="Suggest from MTU", style="Converter.TButton", command=self._suggest_elements)
        self.suggest_btn.grid(row=5, column=2, sticky="new", padx=(10, 0), pady=5)
        self.custom_btn = ttk.Button(inputs, text="Custom...", style="Converter.TButton", command=self._open_custom_elements)
        self.custom_btn.grid(row=6, column=2, sticky="new", padx=(10, 0), pady=(0, 5))
        tk.Label(inputs, textvariable=self.custom_var, bg="#111827", fg="#93C5FD", font=("Segoe UI", 9),
                 anchor="w", justify="left", wraplength=520).grid(row=6, column=1, sticky="w", pady=(0, 5))

        actions = tk.Frame(
            root,
            bg="#111827",
            highlightbackground="#253047",
            highlightthickness=1,
            padx=18,
            pady=14,
        )
        actions.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(14, 14))
        actions.columnconfigure(4, weight=1)
        self.preflight_btn = ttk.Button(actions, text="Preflight", style="Converter.TButton", command=self._preflight)
        self.preflight_btn.grid(row=0, column=0, padx=(0, 8))
        self.preview_btn = ttk.Button(actions, text="Preview Messages", style="Converter.TButton", command=self._preview_messages)
        self.preview_btn.grid(row=0, column=1, padx=(0, 8))
        self.convert_btn = ttk.Button(actions, text="Convert MTU to IPS", style="Primary.Converter.TButton", command=self._convert)
        self.convert_btn.grid(row=0, column=2, padx=(0, 8))
        ttk.Checkbutton(
            actions,
            text="Open Output Folder When Finished",
            variable=self.open_folder_var,
            style="Converter.TCheckbutton",
        ).grid(row=0, column=3, sticky="w")

        self.best_effort_check = ttk.Checkbutton(
            actions,
            text="Best-Effort Anomaly Recovery (editable appearance is unverified)",
            variable=self.best_effort_var,
            style="Converter.TCheckbutton",
        )
        self.best_effort_check.grid(row=1, column=0, columnspan=4, sticky="w", pady=(10, 0))

        activity = tk.Frame(
            root,
            bg="#111827",
            highlightbackground="#253047",
            highlightthickness=1,
            padx=18,
            pady=14,
        )
        activity.grid(row=3, column=0, columnspan=3, sticky="nsew")
        activity.columnconfigure(0, weight=1)
        activity.rowconfigure(2, weight=1)
        tk.Label(
            activity,
            text="Activity",
            bg="#111827",
            fg="#F8FAFC",
            font=("Segoe UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 10))

        self.progress = ttk.Progressbar(
            activity,
            mode="determinate",
            maximum=100,
            variable=self.progress_var,
            style="Converter.Horizontal.TProgressbar",
        )
        self.progress.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        self.log = ScrolledText(
            activity,
            height=18,
            wrap="word",
            state="disabled",
            font=("Consolas", 9),
            bg="#070B12",
            fg="#E5E7EB",
            insertbackground="#F8FAFC",
            relief="flat",
            highlightbackground="#253047",
            highlightthickness=1,
            padx=12,
            pady=10,
        )
        self.log.grid(row=2, column=0, sticky="nsew")

        tk.Label(
            root,
            textvariable=self.status_var,
            bg="#0B1220",
            fg="#CBD5E1",
            font=("Segoe UI", 9),
            anchor="w",
        ).grid(row=4, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        tk.Label(
            root,
            text=f"Windows Jet/DAO  |  {sys.executable}",
            bg="#0B1220",
            fg="#64748B",
            font=("Segoe UI", 8),
            anchor="w",
        ).grid(
            row=5, column=0, columnspan=3, sticky="ew", pady=(4, 0)
        )

    def _browse_mtu(self):
        fn = filedialog.askopenfilename(
            title="Select Compiled MTU",
            filetypes=[("Luminator MTU", "*.mtu"), ("All files", "*.*")],
        )
        if not fn:
            return
        self.mtu_var.set(fn)
        p = Path(fn)
        # Keep following the selected MTU until the user edits these fields.
        if self.out_var.get() in ("", self._auto_output):
            self._auto_output = str(p.with_name(p.stem + "-RECOVERED.ips"))
            self.out_var.set(self._auto_output)
        if self.name_var.get() in ("", self._auto_name):
            self._auto_name = p.stem[:20]
            self.name_var.set(self._auto_name)
        self._append_log(f"Selected MTU: {p}")
        if self.custom_layout is None:
            self._suggest_elements()

    def _browse_output(self):
        initial = Path(self.out_var.get()).name if self.out_var.get() else "RECOVERED.ips"
        fn = filedialog.asksaveasfilename(
            title="Save Recovered IPS",
            defaultextension=".ips",
            initialfile=initial,
            filetypes=[("Luminator IPS", "*.ips"), ("All files", "*.*")],
        )
        if fn:
            self.out_var.set(fn)

    def _browse_donor(self):
        fn = filedialog.askopenfilename(
            title="Locate Donor.ips",
            filetypes=[("Luminator IPS / Access donor", "*.ips *.mdb"), ("All files", "*.*")],
        )
        if fn:
            self.donor_var.set(fn)
            self._save_donor_setting(Path(fn))
            self._append_log(f"Selected donor IPS: {fn}")

    def _save_donor_setting(self, donor: Path):
        try:
            SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
            SETTINGS_FILE.write_text(json.dumps({"donor": str(donor)}, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _append_log(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_busy(self, busy: bool, status: str = ""):
        state = "disabled" if busy else "normal"
        self.preflight_btn.configure(state=state)
        self.preview_btn.configure(state=state)
        self.convert_btn.configure(state=state)
        self.suggest_btn.configure(state=state)
        self.custom_btn.configure(state=state)
        self.best_effort_check.configure(state=state)
        if busy:
            self.progress_var.set(0)
        if status:
            self.status_var.set(status)

    def _set_progress(self, percent: int, status: str):
        self.progress_var.set(max(0, min(100, percent)))
        self.status_var.set(status)

    def _validate_paths(self, need_output: bool, need_donor: bool = False):
        mtu = Path(self.mtu_var.get().strip())
        if not mtu.is_file():
            raise ValueError("Choose a valid .mtu input file.")

        donor = None
        if need_donor:
            donor_text = self.donor_var.get().strip()
            donor = Path(donor_text) if donor_text else None
            if donor is None or not donor.is_file():
                if messagebox.askyesno(
                    APP_TITLE,
                    "Donor.ips, the blank IPS database the recovered project is built from, "
                    "was not found beside the converter.\n\nLocate it now?",
                ):
                    self._browse_donor()
                    donor_text = self.donor_var.get().strip()
                    donor = Path(donor_text) if donor_text else None
            if donor is None or not donor.is_file():
                raise ValueError("Donor.ips is required to write the recovered project.")
            self._save_donor_setting(donor)

        out = Path(self.out_var.get().strip()) if need_output else None
        if need_output:
            if not str(out):
                raise ValueError("Choose an output .ips file.")
            if out.resolve() == mtu.resolve():
                raise ValueError("Output path must be different from the MTU input.")
            if donor is not None and out.resolve() == donor.resolve():
                raise ValueError("Output path must be different from the donor database.")
            out.parent.mkdir(parents=True, exist_ok=True)
        return mtu, donor, out

    def _class_c_layout(self) -> cce.ClassCLayout | cce.CustomLayout:
        if self.custom_layout is not None:
            return self.custom_layout
        chosen = tuple(name for name in cce.ELEMENTS if self.element_vars[name].get())
        return cce.ClassCLayout(chosen)

    def _set_custom_layout(self, layout: cce.CustomLayout | None):
        self.custom_layout = layout
        for name, check in self.element_checks.items():
            if name not in cce.REQUIRED_ELEMENTS:
                check.state(["disabled"] if layout is not None else ["!disabled"])
        self.custom_var.set("Custom elements: " + ", ".join(layout.elements) if layout is not None else "")
        if layout is not None:
            self._append_log("Using custom Class C elements: " + ", ".join(layout.elements))

    def _open_custom_elements(self):
        mtu_text = self.mtu_var.get().strip()
        if not mtu_text or not Path(mtu_text).is_file():
            messagebox.showerror(APP_TITLE, "Choose a valid .mtu input file first.")
            return
        mtu = Path(mtu_text)
        best_effort = self.best_effort_var.get()

        def work():
            try:
                self.events.put(("progress", (20, "Grouping Class C text by role and sign...")))
                model = builder.build_model(mtu, cce.ClassCLayout(cce.ELEMENTS), best_effort=best_effort)
                groups = cce.analyze_groups(model["frames"], model["sign_tables"])
                self.events.put(("groups_done", groups))
            except Exception:
                self.events.put(("error", traceback.format_exc()))

        self._start_worker(work, "Analysing Class C groups...")

    def _suggest_elements(self):
        mtu_text = self.mtu_var.get().strip()
        if not mtu_text or not Path(mtu_text).is_file():
            messagebox.showerror(APP_TITLE, "Choose a valid .mtu input file first.")
            return
        mtu = Path(mtu_text)
        best_effort = self.best_effort_var.get()

        def work():
            try:
                self.events.put(("progress", (20, "Analysing Class C sign layouts...")))
                model = builder.build_model(mtu, None, best_effort=best_effort)
                self.events.put(("suggest_done", (model["class_c_layout"], dict(model["class_c"].usage),
                                                  len(model["class_c"].listings))))
            except Exception:
                self.events.put(("error", traceback.format_exc()))

        self._start_worker(work, "Suggesting Class C elements...")

    def _preview_messages(self):
        mtu_text = self.mtu_var.get().strip()
        if not mtu_text or not Path(mtu_text).is_file():
            messagebox.showerror(APP_TITLE, "Choose a valid .mtu input file first.")
            return
        mtu = Path(mtu_text)
        try:
            layout = self._class_c_layout()
        except ValueError as error:
            messagebox.showerror(APP_TITLE, str(error))
            return
        best_effort = self.best_effort_var.get()

        def work():
            try:
                self.events.put(("progress", (20, "Building the message lists...")))
                model = builder.build_model(mtu, layout, best_effort=best_effort)
                classes = builder.class_message_rows(model)
                # Columns IPS lists for each class; Class A/B follow the donor's
                # listing (its ClassBMsgs table holds PRText only).
                tables = [("Class A", ["Title", "Text"], classes["ClassAMsgs"]),
                          ("Class B", ["PRText"], classes["ClassBMsgs"]),
                          ("Class C", list(layout.elements), classes["ClassCMsgs"])]
                self.events.put(("preview_done", (mtu, tables)))
            except Exception:
                self.events.put(("error", traceback.format_exc()))

        self._start_worker(work, "Building the message lists...")

    def _start_worker(self, target, status):
        if self.worker and self.worker.is_alive():
            return
        self._set_busy(True, status)
        self.worker = threading.Thread(target=target, daemon=True)
        self.worker.start()

    def _preflight(self):
        try:
            mtu, _, _ = self._validate_paths(False, False)
        except Exception as e:
            messagebox.showerror(APP_TITLE, str(e))
            return

        layout = self._class_c_layout()
        best_effort = self.best_effort_var.get()
        donor_text = self.donor_var.get().strip()
        donor = Path(donor_text) if donor_text and Path(donor_text).is_file() else None

        def work():
            try:
                self.events.put(("log", f"Preflight: {mtu.name}  (Class C: {', '.join(layout.elements)})"))
                self.events.put(("progress", (15, "Reading and decoding MTU...")))
                model = builder.build_model(mtu, layout, best_effort=best_effort)
                self.events.put(("progress", (75, "Validating recovered model...")))
                known_font_ids = None
                if donor is not None:
                    try:
                        pythoncom, _, engine, db = builder.open_dao(donor)
                        try:
                            try:
                                binding = builder.probe_load_module(
                                    engine, db, donor, model["compilation_metadata"])
                                model["load_module_binding"] = binding
                                if binding["source"] != "donor":
                                    model["compilation_metadata"]["warnings"].append(
                                        f"Controller module {binding['description']} will be {binding['source']}.")
                            except RuntimeError as error:
                                model["load_module_error"] = str(error)
                            catalog, catalog_warnings = builder.load_sign_catalog(engine, db, donor)
                            model["sign_catalog"] = builder.apply_sign_catalog(
                                model["sign_tables"], catalog, catalog_warnings)
                            known_font_ids, _ = builder.donor_font_bindings(
                                db, model["resources"]["Fonts"])
                        finally:
                            db.Close()
                            pythoncom.CoUninitialize()
                    except Exception as error:
                        self.events.put(("log", f"Load-module/sign/font comparison unavailable: {error}"))
                else:
                    self.events.put(("log", "Donor.ips not found; load-module/sign/font comparison skipped."))
                report = builder.preflight_model(
                    model, set(known_font_ids) if known_font_ids is not None else None)
                self.events.put(("progress", (100, "Preflight complete.")))
                self.events.put(("preflight_done", report))
            except Exception:
                self.events.put(("error", traceback.format_exc()))

        self._start_worker(work, "Parsing and validating MTU...")

    def _convert(self):
        try:
            mtu, donor, out = self._validate_paths(True, True)
        except Exception as e:
            messagebox.showerror(APP_TITLE, str(e))
            return
        project_name = (self.name_var.get().strip() or "RECOVERED")[:20]
        layout = self._class_c_layout()
        best_effort = self.best_effort_var.get()
        if out.exists() and not messagebox.askyesno(APP_TITLE, f"Overwrite existing file?\n\n{out}"):
            return

        def work():
            try:
                self.events.put(("log", f"Converting: {mtu}"))
                self.events.put(("log", f"Donor:     {donor}"))
                self.events.put(("log", f"Output:    {out}"))
                self.events.put(("log", f"Class C:   {', '.join(layout.elements)}"))
                self.events.put(("log", f"Recovery:  {'best-effort (unverified appearance)' if best_effort else 'strict'}"))
                model, verification = builder.build_ips(
                    mtu, donor, out, project_name, layout,
                    lambda percent, status: self.events.put(("progress", (percent, status))),
                    best_effort=best_effort,
                )
                verification["class_c_rows"] = len(model["class_c"].listings)
                self.events.put(("convert_done", (out, verification)))
            except Exception:
                self.events.put(("error", traceback.format_exc()))

        self._start_worker(work, "Writing recovered Jet/IPS database...")

    def _pump_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "suggest_done":
                    layout, usage, messages = payload
                    if self.custom_layout is not None:
                        self._set_custom_layout(None)
                    for name, var in self.element_vars.items():
                        var.set(name in layout.elements)
                    self._append_log(
                        "Suggested Class C elements: " + ", ".join(layout.elements)
                        + f"\n  Messages needing each element (of {messages}): "
                        + ", ".join(f"{name} {usage.get(name, 0)}" for name in cce.ELEMENTS))
                    self._set_busy(False)
                    self._set_progress(100, "Class C elements suggested. Adjust the checkboxes if needed.")
                elif kind == "preview_done":
                    mtu, tables = payload
                    self._set_busy(False)
                    self._set_progress(100, "Message lists: " + ", ".join(
                        f"{name} {len(rows)}" for name, _, rows in tables) + ".")
                    MessagePreviewDialog(self, mtu, tables)
                elif kind == "groups_done":
                    self._set_busy(False)
                    self._set_progress(100, "Name the Class C element groups.")
                    dialog = CustomElementsDialog(self, payload, self.custom_layout)
                    self.wait_window(dialog)
                    if dialog.result == "standard":
                        self._set_custom_layout(None)
                        self.status_var.set("Using the Class C element checkboxes.")
                    elif dialog.result is not None:
                        self._set_custom_layout(dialog.result)
                        self.status_var.set("Custom Class C elements set.")
                elif kind == "progress":
                    percent, status = payload
                    self._set_progress(int(percent), str(status))
                elif kind == "preflight_done":
                    report = payload
                    self._append_log(json.dumps(report, indent=2))
                    self._set_busy(False, "Preflight passed." if report.get("status") == "PASS" else "Preflight failed.")
                    if report.get("status") == "PASS":
                        warnings = report.get("warnings", [])
                        if warnings:
                            self.status_var.set("Preflight passed with warnings. Review the log.")
                        warning_text = ""
                        if warnings:
                            warning_text = "\n\nWarnings:\n" + "\n".join(f"- {warning}" for warning in warnings)
                        message_classes = report.get("message_classes", {})
                        class_text = ", ".join(
                            f"{letter}: {count}" for letter, count in message_classes.items()
                        ) or "none"
                        font_categories = report.get("font_categories", {})
                        known_fonts = font_categories.get("known")
                        font_text = (
                            f"known {known_fonts}, unknown {font_categories.get('unknown')}"
                            if known_fonts is not None else "not compared to a donor"
                        )
                        graphic_categories = report.get("graphic_categories", {})
                        notify = messagebox.showwarning if warnings else messagebox.showinfo
                        notify(
                            APP_TITLE,
                            ("Preflight passed with warnings.\n\n" if warnings else "Preflight passed.\n\n") +
                            f"Class C elements: {', '.join((report.get('class_c_layout') or {}).get('elements', []))}\n"
                            f"Messages: {report.get('message_pairs')}\n"
                            f"Messages by class: {class_text}\n"
                            f"Frame rows: {report.get('frame_rows')}\n"
                            f"Fonts: {report.get('fonts')} ({font_text})\n"
                            f"Graphics: {report.get('graphics')} "
                            f"(colored {graphic_categories.get('colored', 0)}, "
                            f"monochrome {graphic_categories.get('monochrome', 0)})"
                            f"{warning_text}",
                        )
                    else:
                        messagebox.showerror(APP_TITLE, "Preflight failed. See the log for details.")
                elif kind == "convert_done":
                    out, verification = payload
                    self._append_log(json.dumps(verification, indent=2))
                    self._set_busy(False, f"Conversion complete: {out.name}")
                    warnings = verification.get("warnings", [])
                    notify = messagebox.showwarning if warnings else messagebox.showinfo
                    warning_text = (
                        f"\n\n{len(warnings)} warning(s). Review the log and verification report; "
                        "database verification does not certify rendered appearance."
                        if warnings else ""
                    )
                    notify(
                        APP_TITLE,
                        "Conversion complete. Database row counts and original MTU bytes verified.\n\n"
                        f"{out}\n\nA .verify.json report was written beside the IPS file."
                        f"{warning_text}",
                    )
                    if self.open_folder_var.get():
                        try:
                            os.startfile(str(out.parent))
                        except Exception:
                            pass
                elif kind == "error":
                    text = str(payload)
                    self._append_log(text)
                    error_path = HERE / "conversion_error.txt"
                    try:
                        error_path.write_text(text, encoding="utf-8")
                    except Exception:
                        error_path = Path.cwd() / "conversion_error.txt"
                        try:
                            error_path.write_text(text, encoding="utf-8")
                        except Exception:
                            pass
                    self._set_busy(False, "Conversion failed. See the log.")
                    hint = ""
                    if "[DATABASE_IN_USE]" in text:
                        hint = (
                            "\n\nJet/DAO is available, but the database is currently open exclusively. "
                            "Close Luminator IPS, Access, or another converter using that database, "
                            "then retry.\n\n"
                            "Do not delete a Jet lock file while another user or program may still be using it."
                        )
                    elif "[DAO_OPEN_FAILED]" in text:
                        hint = (
                            "\n\npywin32 loaded correctly, but Microsoft Jet/DAO could not be opened "
                            "from this Python process. This is usually a 32/64-bit mismatch. "
                            "Close the GUI and run SETUP_AND_RUN.cmd; it probes DAO bitness and "
                            "selects a matching Python automatically.\n\n"
                            f"GUI Python: {sys.executable}"
                        )
                    elif "[PYWIN32_IMPORT_FAILED]" in text:
                        hint = (
                            "\n\npywin32 failed to import in this exact Python runtime. "
                            "Run SETUP_AND_RUN.cmd again and attach launcher_diagnostics.txt if it persists.\n\n"
                            f"GUI Python: {sys.executable}"
                        )
                    messagebox.showerror(
                        APP_TITLE,
                        "Conversion failed." + hint + f"\n\nSee {error_path.name} for the full traceback.",
                    )
        except queue.Empty:
            pass
        self.after(100, self._pump_events)


class CustomElementsDialog(tk.Toplevel):
    """Name Class C element groups (one role on one physical sign).

    Rows sharing a name become one element.  ``result`` is a CustomLayout,
    "standard" to return to the checkboxes, or None when cancelled.
    """

    def __init__(self, parent: tk.Tk, groups: list, current: cce.CustomLayout | None):
        super().__init__(parent)
        self.title("Custom Class C Elements")
        self.configure(background="#0B1220")
        self.geometry("1240x580")
        self.minsize(820, 420)
        # No transient(): on Windows it removes the maximize button.  grab_set() keeps it modal.
        self.result = None
        self.groups = {f"g{index}": group for index, group in enumerate(groups)}
        self.names = {key: (current.name_for(group.role, group.sign) if current else group.role)
                      for key, group in self.groups.items()}
        # Output order of the elements (IPS listing columns); groups only set names.
        self.element_order: list[str] = list(current.elements) if current else []

        frame = tk.Frame(self, bg="#0B1220", padx=16, pady=14)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        intro = tk.Label(
            frame, bg="#0B1220", fg="#CBD5E1", font=("Segoe UI", 9), justify="left", anchor="w",
            text=("Each row is one role on one sign. Rows with the same element name become one element "
                  "(merge); give a row its own name to split it out. Select rows, then type or pick a name. "
                  f"Choose {cce.UNLINKED} to keep a row's text on the signs without linking it to any element."),
        )
        intro.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 10))
        intro.bind("<Configure>", lambda event: intro.configure(wraplength=max(200, event.width - 10)))

        style = ttk.Style(self)
        style.configure("Custom.Treeview", background="#0F172A", fieldbackground="#0F172A",
                        foreground="#E5E7EB", rowheight=22, bordercolor="#253047")
        style.configure("Custom.Treeview.Heading", background="#172033", foreground="#F8FAFC",
                        font=("Segoe UI", 9, "bold"))
        # clam lightens hovered headings to near-white; keep them dark and readable.
        style.map("Custom.Treeview.Heading", background=[("active", "#22304A"), ("pressed", "#1D4ED8")],
                  foreground=[("active", "#F8FAFC")])
        style.map("Custom.Treeview", background=[("selected", "#1D4ED8")])
        columns = ("element", "role", "sign", "messages", "examples")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="extended",
                                 style="Custom.Treeview")
        self.headings = {}
        self.sort_state = (None, False)
        for column, title, width, stretch in (
                ("element", "Element", 150, False), ("role", "Role", 120, False),
                ("sign", "Sign", 260, False), ("messages", "Messages", 80, False),
                ("examples", "Examples", 380, True)):
            self.headings[column] = title
            if column in ("element", "role", "sign"):
                self.tree.heading(column, text=title, command=lambda c=column: self._sort(c))
            else:
                self.tree.heading(column, text=title)
            self.tree.column(column, width=width, stretch=stretch, anchor="e" if column == "messages" else "w")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.grid(row=1, column=0, sticky="nsew")
        scroll.grid(row=1, column=1, sticky="ns")
        for key, group in self.groups.items():
            self.tree.insert("", "end", iid=key, values=(
                self.names[key], group.role, group.label, group.messages, " | ".join(group.samples)))
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        order_panel = tk.Frame(frame, bg="#111827", highlightbackground="#253047", highlightthickness=1,
                               padx=10, pady=8)
        order_panel.grid(row=1, column=2, rowspan=2, sticky="ns", padx=(12, 0))
        order_panel.rowconfigure(1, weight=1)
        tk.Label(order_panel, text="Element Order", bg="#111827", fg="#F8FAFC",
                 font=("Segoe UI", 9, "bold")).grid(row=0, column=0, columnspan=2, sticky="w")
        self.order_list = tk.Listbox(
            order_panel, width=22, activestyle="none", exportselection=False, bg="#0F172A", fg="#E5E7EB",
            selectbackground="#1D4ED8", selectforeground="#FFFFFF", highlightthickness=1,
            highlightbackground="#253047", relief="flat", font=("Segoe UI", 9))
        self.order_list.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(6, 6))
        self.order_list.bind("<Button-1>", self._drag_start)
        self.order_list.bind("<B1-Motion>", self._drag_motion)
        self.order_list.bind("<ButtonRelease-1>", lambda _event: setattr(self, "_drag_index", None))
        self._drag_index = None
        ttk.Button(order_panel, text="Move Up", style="Converter.TButton",
                   command=lambda: self._move_element(-1)).grid(row=2, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(order_panel, text="Move Down", style="Converter.TButton",
                   command=lambda: self._move_element(1)).grid(row=2, column=1, sticky="ew")
        tk.Label(order_panel, text="Left-to-right column\norder in IPS", bg="#111827", fg="#94A3B8",
                 font=("Segoe UI", 8), justify="left").grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))

        edit = tk.Frame(frame, bg="#0B1220")
        edit.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        tk.Label(edit, text="Element Name for Selected Rows", bg="#0B1220", fg="#CBD5E1",
                 font=("Segoe UI", 9)).pack(side="left")
        self.name_var = tk.StringVar()
        self.name_box = ttk.Combobox(edit, textvariable=self.name_var, width=28, style="Converter.TCombobox")
        self.name_box.pack(side="left", padx=8)
        self.name_box.bind("<Return>", lambda _event: self._apply_name())
        ttk.Button(edit, text="Apply", style="Converter.TButton", command=self._apply_name).pack(side="left")
        ttk.Button(edit, text="Use Role Names", style="Converter.TButton",
                   command=self._reset).pack(side="left", padx=(8, 0))
        self._refresh_names()

        buttons = tk.Frame(frame, bg="#0B1220")
        buttons.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(12, 0))
        ttk.Button(buttons, text="Load Preset...", style="Converter.TButton", command=self._load).pack(side="left")
        ttk.Button(buttons, text="Save Preset...", style="Converter.TButton",
                   command=self._save).pack(side="left", padx=(8, 0))
        ttk.Button(buttons, text="Use Checkboxes Instead", style="Converter.TButton",
                   command=self._standard).pack(side="left", padx=(8, 0))
        ttk.Button(buttons, text="Cancel", style="Converter.TButton", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="OK", style="Primary.Converter.TButton",
                   command=self._ok).pack(side="right", padx=(0, 8))
        self.grab_set()

    def _sort(self, column: str):
        previous, descending = self.sort_state
        descending = not descending if previous == column else False
        self.sort_state = (column, descending)
        original = {key: index for index, key in enumerate(self.groups)}

        def key(item):
            group = self.groups[item]
            role_rank = cce.ELEMENTS.index(group.role)
            if column == "element":
                name = self.names[item]
                primary = (name == cce.UNLINKED, name.lower())
            elif column == "role":
                primary = (role_rank,)
            else:
                primary = (group.label.lower(),)
            # Ties keep the analysis order (role, then sign priority).
            return primary + (original[item],)

        for index, item in enumerate(sorted(self.groups, key=key, reverse=descending)):
            self.tree.move(item, "", index)
        for name, title in self.headings.items():
            arrow = (" \u25bc" if descending else " \u25b2") if name == column else ""
            self.tree.heading(name, text=title + arrow)

    def _refresh_names(self):
        names = [name for name in dict.fromkeys(self.names[key] for key in self.groups) if name != cce.UNLINKED]
        self.name_box.configure(values=names + [cce.UNLINKED])
        for key in self.groups:
            self.tree.set(key, "element", self.names[key])
        # Keep the chosen order; new names go last, unused names drop out.
        self.element_order = [name for name in self.element_order if name in names]
        self.element_order += [name for name in names if name not in self.element_order]
        self._show_order()

    def _show_order(self, selected: str | None = None):
        if selected is None:
            current = self.order_list.curselection()
            selected = self.order_list.get(current[0]) if current else None
        self.order_list.delete(0, "end")
        for name in self.element_order:
            self.order_list.insert("end", name)
        if selected in self.element_order:
            index = self.element_order.index(selected)
            self.order_list.selection_set(index)
            self.order_list.see(index)

    def _drag_start(self, event):
        index = self.order_list.nearest(event.y)
        self._drag_index = index if 0 <= index < len(self.element_order) else None

    def _drag_motion(self, event):
        if self._drag_index is None:
            return
        target = self.order_list.nearest(event.y)
        if target == self._drag_index or not 0 <= target < len(self.element_order):
            return
        name = self.element_order.pop(self._drag_index)
        self.element_order.insert(target, name)
        self._drag_index = target
        self._show_order(name)

    def _move_element(self, step: int):
        current = self.order_list.curselection()
        if not current:
            return
        index = current[0]
        target = index + step
        if not 0 <= target < len(self.element_order):
            return
        order = self.element_order
        order[index], order[target] = order[target], order[index]
        self._show_order(order[target])

    def _on_select(self, _event=None):
        selected = self.tree.selection()
        names = {self.names[key] for key in selected}
        if len(names) == 1:
            self.name_var.set(names.pop())

    def _apply_name(self):
        name = self.name_var.get().strip()
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo(APP_TITLE, "Select one or more rows first.", parent=self)
            return
        try:
            if name != cce.UNLINKED:
                cce.validate_element_names([name])
        except ValueError as error:
            messagebox.showerror(APP_TITLE, str(error), parent=self)
            return
        if name != cce.UNLINKED and name not in self.element_order:
            # A new name takes the place of the earliest name it replaces.
            positions = [self.element_order.index(self.names[key]) for key in selected
                         if self.names[key] in self.element_order]
            if positions:
                self.element_order.insert(min(positions), name)
        for key in selected:
            self.names[key] = name
        self._refresh_names()

    def _reset(self):
        for key, group in self.groups.items():
            self.names[key] = group.role
        self.element_order = []
        self._refresh_names()

    def _layout(self) -> cce.CustomLayout:
        assignments = {(group.role, group.sign): self.names[key] for key, group in self.groups.items()}
        return cce.CustomLayout.build(assignments, order=self.element_order)

    def _load(self):
        fn = filedialog.askopenfilename(parent=self, title="Load Class C Element Preset",
                                        filetypes=[("Class C preset", "*.json"), ("All files", "*.*")])
        if not fn:
            return
        try:
            preset = cce.load_preset(fn)
        except Exception as error:
            messagebox.showerror(APP_TITLE, f"Could not load preset:\n{error}", parent=self)
            return
        for key, group in self.groups.items():
            self.names[key] = preset.name_for(group.role, group.sign)
        self.element_order = list(preset.elements)
        self._refresh_names()

    def _save(self):
        try:
            layout = self._layout()
        except ValueError as error:
            messagebox.showerror(APP_TITLE, str(error), parent=self)
            return
        fn = filedialog.asksaveasfilename(parent=self, title="Save Class C Element Preset",
                                          defaultextension=".json", initialfile="class-c-elements.json",
                                          filetypes=[("Class C preset", "*.json"), ("All files", "*.*")])
        if fn:
            cce.save_preset(layout, fn)

    def _standard(self):
        self.result = "standard"
        self.destroy()

    def _ok(self):
        try:
            self.result = self._layout()
        except ValueError as error:
            messagebox.showerror(APP_TITLE, str(error), parent=self)
            return
        self.destroy()


class MessageTable(tk.Frame):
    """Searchable, sortable list of one message class."""

    def __init__(self, parent, columns: list[str], rows: list[dict]):
        super().__init__(parent, bg="#0B1220", padx=10, pady=10)
        self.columns = ["MsgCode"] + list(columns)
        self.rows = [[int(row["MsgCode"])] + [str(row.get(name) or "") for name in columns] for row in rows]
        self.sort_state = (0, False)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        top = tk.Frame(self, bg="#0B1220")
        top.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        tk.Label(top, text="Search", bg="#0B1220", fg="#CBD5E1", font=("Segoe UI", 9)).pack(side="left")
        self.search_var = tk.StringVar()
        self.search = ttk.Entry(top, textvariable=self.search_var, width=36, style="Converter.TEntry")
        self.search.pack(side="left", padx=8)
        self.search_var.trace_add("write", lambda *_args: self._populate())
        self.count_var = tk.StringVar()
        tk.Label(top, textvariable=self.count_var, bg="#0B1220", fg="#94A3B8",
                 font=("Segoe UI", 9)).pack(side="left", padx=(8, 0))
        tk.Label(top, text="^ separates frames, \u00f7 separates lines", bg="#0B1220", fg="#94A3B8",
                 font=("Segoe UI", 8)).pack(side="right")

        ids = [f"c{index}" for index in range(len(self.columns))]
        self.tree = ttk.Treeview(self, columns=ids, show="headings", selectmode="extended", style="Custom.Treeview")
        for index, (column_id, name) in enumerate(zip(ids, self.columns)):
            self.tree.heading(column_id, text=name, command=lambda i=index: self._sort(i))
            self.tree.column(column_id, width=90 if index == 0 else 240, stretch=index > 0,
                             anchor="e" if index == 0 else "w")
        yscroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=1, column=0, sticky="nsew")
        yscroll.grid(row=1, column=1, sticky="ns")
        xscroll.grid(row=2, column=0, sticky="ew")
        self._populate()

    def visible_rows(self) -> list[list]:
        needle = self.search_var.get().strip().lower()
        rows = [row for row in self.rows if not needle or any(needle in str(value).lower() for value in row)]
        index, descending = self.sort_state
        key = (lambda row: row[0]) if index == 0 else (lambda row: (row[index].lower(), row[0]))
        return sorted(rows, key=key, reverse=descending)

    def is_filtered(self) -> bool:
        return bool(self.search_var.get().strip())

    def _populate(self):
        self.tree.delete(*self.tree.get_children())
        rows = self.visible_rows()
        for row in rows:
            self.tree.insert("", "end", values=row)
        total = len(self.rows)
        self.count_var.set(f"{len(rows)} of {total} messages" if len(rows) != total else f"{total} messages")

    def _sort(self, index: int):
        previous, descending = self.sort_state
        self.sort_state = (index, not descending if previous == index else False)
        for column, name in enumerate(self.columns):
            arrow = (" \u25bc" if self.sort_state[1] else " \u25b2") if column == index else ""
            self.tree.heading(f"c{column}", text=name + arrow)
        self._populate()


class MessagePreviewDialog(tk.Toplevel):
    """Class A, B and C message lists as IPS will show them, with Excel export."""

    def __init__(self, parent: tk.Tk, mtu: Path, tables: list[tuple[str, list[str], list[dict]]]):
        super().__init__(parent)
        self.title(f"Message Lists - {mtu.name}")
        self.configure(background="#0B1220")
        self.geometry("1180x640")
        self.minsize(720, 400)
        self.mtu = mtu

        style = ttk.Style(self)
        style.configure("Custom.Treeview", background="#0F172A", fieldbackground="#0F172A",
                        foreground="#E5E7EB", rowheight=22, bordercolor="#253047")
        style.configure("Custom.Treeview.Heading", background="#172033", foreground="#F8FAFC",
                        font=("Segoe UI", 9, "bold"))
        style.map("Custom.Treeview.Heading", background=[("active", "#22304A"), ("pressed", "#1D4ED8")],
                  foreground=[("active", "#F8FAFC")])
        style.map("Custom.Treeview", background=[("selected", "#1D4ED8")])
        style.configure("Preview.TNotebook", background="#0B1220", borderwidth=0)
        style.configure("Preview.TNotebook.Tab", background="#172033", foreground="#CBD5E1",
                        padding=(14, 6), font=("Segoe UI", 9, "bold"))
        style.map("Preview.TNotebook.Tab", background=[("selected", "#1D4ED8"), ("active", "#22304A")],
                  foreground=[("selected", "#FFFFFF")])

        frame = tk.Frame(self, bg="#0B1220", padx=16, pady=14)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        self.notebook = ttk.Notebook(frame, style="Preview.TNotebook")
        self.notebook.grid(row=0, column=0, sticky="nsew")
        self.tables: list[tuple[str, MessageTable]] = []
        for name, columns, rows in tables:
            table = MessageTable(self.notebook, columns, rows)
            self.notebook.add(table, text=f"{name} ({len(rows)})")
            self.tables.append((name, table))
        # Open on Class C, the list most users check.
        self.notebook.select(len(self.tables) - 1)

        buttons = tk.Frame(frame, bg="#0B1220")
        buttons.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        ttk.Button(buttons, text="Export to Excel...", style="Primary.Converter.TButton",
                   command=self._export).pack(side="left")
        tk.Label(buttons, text="One sheet per class; each sheet uses its tab's search and sort.",
                 bg="#0B1220", fg="#94A3B8", font=("Segoe UI", 8)).pack(side="left", padx=(10, 0))
        ttk.Button(buttons, text="Close", style="Converter.TButton", command=self.destroy).pack(side="right")

    def _export(self):
        fn = filedialog.asksaveasfilename(
            parent=self, title="Export Message Lists", defaultextension=".xlsx",
            initialfile=f"{self.mtu.stem} - Messages.xlsx",
            filetypes=[("Excel workbook", "*.xlsx"), ("All files", "*.*")])
        if not fn:
            return
        sheets = [(name, table.columns, table.visible_rows()) for name, table in self.tables]
        try:
            xlsx_export.write_xlsx_sheets(fn, sheets)
        except Exception as error:
            messagebox.showerror(APP_TITLE, f"Could not export:\n{error}", parent=self)
            return
        summary = "\n".join(
            f"{name}: {len(rows)} messages" + (" (search filter applied)" if table.is_filtered() else "")
            for (name, _, rows), (_, table) in zip(sheets, self.tables))
        messagebox.showinfo(APP_TITLE, f"Exported to:\n{fn}\n\n{summary}", parent=self)


if __name__ == "__main__":
    ConverterUI().mainloop()

"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build_ips_windows as builder
import mtu_reverse as mr

APP_TITLE = "Luminator MTU → IPS Converter"
SETTINGS_DIR = Path(os.environ.get("APPDATA", Path.home())) / "LuminatorMTUtoIPS"
SETTINGS_FILE = SETTINGS_DIR / "settings.json"


def _default_donor() -> str:
    candidates = [HERE / "Donor.ips"]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        donor = Path(data.get("donor", ""))
        if donor.is_file():
            return str(donor)
    except Exception:
        pass
    return ""


class ConverterUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("860x700")
        self.minsize(720, 560)
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.worker = None

        self.mtu_var = tk.StringVar()
        self.out_var = tk.StringVar()
        self.donor_var = tk.StringVar(value=_default_donor())
        self.name_var = tk.StringVar(value="RECOVERED")
        self.profile_var = tk.StringVar(value="Auto")
        self.status_var = tk.StringVar(value="Select an MTU file to begin.")
        self.open_folder_var = tk.BooleanVar(value=True)

        self._build_ui()
        self.after(100, self._pump_events)

    def _build_ui(self):
        root = ttk.Frame(self, padding=14)
        root.pack(fill="both", expand=True)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(9, weight=1)

        ttk.Label(root, text=APP_TITLE, font=("Segoe UI", 16, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 4)
        )
        ttk.Label(
            root,
            text=("Reconstructs an editable IPS project from a compiled MTU. Supports both legacy "
                  "Route / Destination / SmallSide and expanded five-field Class C projects."),
            wraplength=760,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 14))

        ttk.Label(root, text="Input MTU:").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=5)
        ttk.Entry(root, textvariable=self.mtu_var).grid(row=2, column=1, sticky="ew", pady=5)
        ttk.Button(root, text="Browse…", command=self._browse_mtu).grid(row=2, column=2, padx=(8, 0), pady=5)

        ttk.Label(root, text="Output IPS:").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=5)
        ttk.Entry(root, textvariable=self.out_var).grid(row=3, column=1, sticky="ew", pady=5)
        ttk.Button(root, text="Save as…", command=self._browse_output).grid(row=3, column=2, padx=(8, 0), pady=5)

        ttk.Label(root, text="Donor IPS:").grid(row=4, column=0, sticky="w", padx=(0, 8), pady=5)
        ttk.Entry(root, textvariable=self.donor_var).grid(row=4, column=1, sticky="ew", pady=5)
        ttk.Button(root, text="Browse…", command=self._browse_donor).grid(row=4, column=2, padx=(8, 0), pady=5)

        ttk.Label(root, text="Project name:").grid(row=5, column=0, sticky="w", padx=(0, 8), pady=5)
        ttk.Entry(root, textvariable=self.name_var).grid(row=5, column=1, sticky="ew", pady=5)
        ttk.Label(root, text="IPS stores max 20 chars").grid(row=5, column=2, sticky="e", padx=(8, 0), pady=5)

        ttk.Label(root, text="Class C schema:").grid(row=6, column=0, sticky="w", padx=(0, 8), pady=5)
        profile = ttk.Combobox(
            root,
            textvariable=self.profile_var,
            state="readonly",
            values=("Auto", "Legacy (Route / Destination / SmallSide)",
                    "Expanded (Route / Top / Bottom / Side / RouteSide)"),
        )
        profile.grid(row=6, column=1, sticky="ew", pady=5)
        ttk.Label(root, text="Auto recommended").grid(row=6, column=2, sticky="e", padx=(8, 0), pady=5)

        buttons = ttk.Frame(root)
        buttons.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(12, 8))
        buttons.columnconfigure(3, weight=1)
        self.preflight_btn = ttk.Button(buttons, text="Preflight", command=self._preflight)
        self.preflight_btn.grid(row=0, column=0, padx=(0, 8))
        self.convert_btn = ttk.Button(buttons, text="Convert MTU → IPS", command=self._convert)
        self.convert_btn.grid(row=0, column=1, padx=(0, 8))
        ttk.Checkbutton(
            buttons,
            text="Open output folder when finished",
            variable=self.open_folder_var,
        ).grid(row=0, column=2, sticky="w")

        self.progress = ttk.Progressbar(root, mode="indeterminate")
        self.progress.grid(row=8, column=0, columnspan=3, sticky="ew", pady=(0, 8))

        self.log = ScrolledText(root, height=18, wrap="word", state="disabled", font=("Consolas", 9))
        self.log.grid(row=9, column=0, columnspan=3, sticky="nsew")

        ttk.Label(root, textvariable=self.status_var, wraplength=760).grid(
            row=10, column=0, columnspan=3, sticky="ew", pady=(8, 0)
        )
        ttk.Label(
            root,
            text=("Windows requirement: Microsoft Jet/DAO and pywin32. "
                  f"Runtime: {sys.executable}"),
            foreground="#555555",
        ).grid(row=11, column=0, columnspan=3, sticky="w", pady=(5, 0))

    def _browse_mtu(self):
        fn = filedialog.askopenfilename(
            title="Select compiled MTU",
            filetypes=[("Luminator MTU", "*.mtu"), ("All files", "*.*")],
        )
        if not fn:
            return
        self.mtu_var.set(fn)
        p = Path(fn)
        if not self.out_var.get():
            self.out_var.set(str(p.with_name(p.stem + "-RECOVERED.ips")))
        if self.name_var.get() == "RECOVERED":
            self.name_var.set(p.stem[:20])
        self._append_log(f"Selected MTU: {p}")

    def _browse_output(self):
        initial = Path(self.out_var.get()).name if self.out_var.get() else "RECOVERED.ips"
        fn = filedialog.asksaveasfilename(
            title="Save recovered IPS",
            defaultextension=".ips",
            initialfile=initial,
            filetypes=[("Luminator IPS", "*.ips"), ("All files", "*.*")],
        )
        if fn:
            self.out_var.set(fn)

    def _browse_donor(self):
        fn = filedialog.askopenfilename(
            title="Select a blank/donor Luminator IPS database (Donor.ips included)",
            filetypes=[("Luminator IPS / Access donor", "*.ips *.mdb"), ("All files", "*.*")],
        )
        if fn:
            self.donor_var.set(fn)
            self._save_donor_setting(Path(fn))
            self._append_log(f"Selected donor IPS: {fn}")

    def _save_donor_setting(self, donor: Path):
        try:
            SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
            SETTINGS_FILE.write_text(json.dumps({"donor": str(donor)}, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _append_log(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_busy(self, busy: bool, status: str = ""):
        state = "disabled" if busy else "normal"
        self.preflight_btn.configure(state=state)
        self.convert_btn.configure(state=state)
        if busy:
            self.progress.start(10)
        else:
            self.progress.stop()
        if status:
            self.status_var.set(status)

    def _validate_paths(self, need_output: bool, need_donor: bool = False):
        mtu = Path(self.mtu_var.get().strip())
        if not mtu.is_file():
            raise ValueError("Choose a valid .mtu input file.")

        donor = None
        if need_donor:
            donor_text = self.donor_var.get().strip()
            donor = Path(donor_text) if donor_text else None
            if donor is None or not donor.is_file():
                if messagebox.askyesno(
                    APP_TITLE,
                    "A donor IPS database is required to write the recovered project.\n\n"
                    "Donor.ips is included with this converter.\n\nSelect it now?",
                ):
                    self._browse_donor()
                    donor_text = self.donor_var.get().strip()
                    donor = Path(donor_text) if donor_text else None
            if donor is None or not donor.is_file():
                raise ValueError("Choose a valid donor .ips/.mdb file (Donor.ips is included).")
            self._save_donor_setting(donor)

        out = Path(self.out_var.get().strip()) if need_output else None
        if need_output:
            if not str(out):
                raise ValueError("Choose an output .ips file.")
            if out.resolve() == mtu.resolve():
                raise ValueError("Output path must be different from the MTU input.")
            if donor is not None and out.resolve() == donor.resolve():
                raise ValueError("Output path must be different from the donor database.")
            out.parent.mkdir(parents=True, exist_ok=True)
        return mtu, donor, out

    def _profile_key(self):
        v = self.profile_var.get()
        if v.startswith("Legacy"):
            return "legacy"
        if v.startswith("Expanded"):
            return "expanded"
        return "auto"

    def _start_worker(self, target, status):
        if self.worker and self.worker.is_alive():
            return
        self._set_busy(True, status)
        self.worker = threading.Thread(target=target, daemon=True)
        self.worker.start()

    def _preflight(self):
        try:
            mtu, _, _ = self._validate_paths(False, False)
        except Exception as e:
            messagebox.showerror(APP_TITLE, str(e))
            return

        profile_key = self._profile_key()

        def work():
            try:
                self.events.put(("log", f"Preflight: {mtu.name}  (Class C: {profile_key})"))
                model = builder.build_model(mtu, profile_key)
                report = builder.preflight_model(model)
                cc = mr.reconstruct_class_c_by_profile(
                    model["frames"], model["sign_tables"], model["class_c_profile"]
                )
                report["class_c_rows"] = len(cc)
                self.events.put(("preflight_done", report))
            except Exception:
                self.events.put(("error", traceback.format_exc()))

        self._start_worker(work, "Parsing and validating MTU…")

    def _convert(self):
        try:
            mtu, donor, out = self._validate_paths(True, True)
        except Exception as e:
            messagebox.showerror(APP_TITLE, str(e))
            return
        project_name = (self.name_var.get().strip() or "RECOVERED")[:20]
        profile_key = self._profile_key()
        if out.exists() and not messagebox.askyesno(APP_TITLE, f"Overwrite existing file?\n\n{out}"):
            return

        def work():
            try:
                self.events.put(("log", f"Converting: {mtu}"))
                self.events.put(("log", f"Donor:     {donor}"))
                self.events.put(("log", f"Output:    {out}"))
                self.events.put(("log", f"Class C:   {profile_key}"))
                model, verification = builder.build_ips(mtu, donor, out, project_name, profile_key)
                cc = mr.reconstruct_class_c_by_profile(
                    model["frames"], model["sign_tables"], model["class_c_profile"]
                )
                verification["class_c_rows"] = len(cc)
                self.events.put(("convert_done", (out, verification)))
            except Exception:
                self.events.put(("error", traceback.format_exc()))

        self._start_worker(work, "Writing recovered Jet/IPS database…")

    def _pump_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "preflight_done":
                    report = payload
                    self._append_log(json.dumps(report, indent=2))
                    self._set_busy(False, "Preflight passed." if report.get("status") == "PASS" else "Preflight failed.")
                    if report.get("status") == "PASS":
                        messagebox.showinfo(
                            APP_TITLE,
                            "Preflight passed.\n\n"
                            f"Class C schema: {report.get('class_c_profile')}\n"
                            f"Messages: {report.get('message_pairs')}\n"
                            f"Class C rows: {report.get('class_c_rows')}\n"
                            f"Frame rows: {report.get('frame_rows')}\n"
                            f"Fonts: {report.get('fonts')}\nGraphics: {report.get('graphics')}",
                        )
                    else:
                        messagebox.showerror(APP_TITLE, "Preflight failed. See the log for details.")
                elif kind == "convert_done":
                    out, verification = payload
                    self._append_log(json.dumps(verification, indent=2))
                    self._set_busy(False, f"Conversion complete: {out.name}")
                    messagebox.showinfo(
                        APP_TITLE,
                        "Conversion complete and post-write verification passed.\n\n"
                        f"{out}\n\nA .verify.json report was written beside the IPS file.",
                    )
                    if self.open_folder_var.get():
                        try:
                            os.startfile(str(out.parent))
                        except Exception:
                            pass
                elif kind == "error":
                    text = str(payload)
                    self._append_log(text)
                    error_path = HERE / "conversion_error.txt"
                    try:
                        error_path.write_text(text, encoding="utf-8")
                    except Exception:
                        error_path = Path.cwd() / "conversion_error.txt"
                        try:
                            error_path.write_text(text, encoding="utf-8")
                        except Exception:
                            pass
                    self._set_busy(False, "Conversion failed. See the log.")
                    hint = ""
                    if "[DAO_OPEN_FAILED]" in text:
                        hint = (
                            "\n\npywin32 loaded correctly, but Microsoft Jet/DAO could not be opened "
                            "from this Python process. This is usually a 32/64-bit mismatch. "
                            "Close the GUI and run SETUP_AND_RUN.cmd; it probes DAO bitness and "
                            "selects a matching Python automatically.\n\n"
                            f"GUI Python: {sys.executable}"
                        )
                    elif "[PYWIN32_IMPORT_FAILED]" in text:
                        hint = (
                            "\n\npywin32 failed to import in this exact Python runtime. "
                            "Run SETUP_AND_RUN.cmd again and attach launcher_diagnostics.txt if it persists.\n\n"
                            f"GUI Python: {sys.executable}"
                        )
                    messagebox.showerror(
                        APP_TITLE,
                        "Conversion failed." + hint + f"\n\nSee {error_path.name} for the full traceback.",
                    )
        except queue.Empty:
            pass
        self.after(100, self._pump_events)


if __name__ == "__main__":
    ConverterUI().mainloop()
"""

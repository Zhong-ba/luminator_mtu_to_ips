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
import mtu_reverse as mr

APP_TITLE = "Luminator MTU to IPS Converter"
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
        self.geometry("980x760")
        self.minsize(820, 620)
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.worker = None

        self.mtu_var = tk.StringVar()
        self.out_var = tk.StringVar()
        self.donor_var = tk.StringVar(value=_default_donor())
        self.name_var = tk.StringVar(value="RECOVERED")
        self.profile_var = tk.StringVar(value="Auto")
        self.status_var = tk.StringVar(value="Select an MTU file to begin.")
        self.open_folder_var = tk.BooleanVar(value=True)
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

        tk.Label(inputs, text="Donor IPS", **label_options).grid(row=3, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(inputs, textvariable=self.donor_var, style="Converter.TEntry").grid(row=3, column=1, sticky="ew", pady=5)
        ttk.Button(inputs, text="Browse", style="Converter.TButton", command=self._browse_donor).grid(row=3, column=2, padx=(10, 0), pady=5)

        tk.Label(inputs, text="Project name", **label_options).grid(row=4, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(inputs, textvariable=self.name_var, style="Converter.TEntry").grid(row=4, column=1, sticky="ew", pady=5)
        tk.Label(inputs, text="20 characters max", bg="#111827", fg="#94A3B8", font=("Segoe UI", 8)).grid(row=4, column=2, sticky="e", padx=(10, 0), pady=5)

        tk.Label(inputs, text="Class-C schema", **label_options).grid(row=5, column=0, sticky="w", padx=(0, 12), pady=5)
        profile = ttk.Combobox(
            inputs,
            textvariable=self.profile_var,
            state="readonly",
            style="Converter.TCombobox",
            values=("Auto", "Legacy (Route / Destination / SmallSide)",
                    "Expanded (Route / Top / Bottom / Side / RouteSide)"),
        )
        profile.grid(row=5, column=1, sticky="ew", pady=5)
        tk.Label(inputs, text="Automatic", bg="#111827", fg="#94A3B8", font=("Segoe UI", 8)).grid(row=5, column=2, sticky="e", padx=(10, 0), pady=5)

        actions = tk.Frame(
            root,
            bg="#111827",
            highlightbackground="#253047",
            highlightthickness=1,
            padx=18,
            pady=14,
        )
        actions.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(14, 14))
        actions.columnconfigure(3, weight=1)
        self.preflight_btn = ttk.Button(actions, text="Preflight", style="Converter.TButton", command=self._preflight)
        self.preflight_btn.grid(row=0, column=0, padx=(0, 8))
        self.convert_btn = ttk.Button(actions, text="Convert MTU to IPS", style="Primary.Converter.TButton", command=self._convert)
        self.convert_btn.grid(row=0, column=1, padx=(0, 8))
        ttk.Checkbutton(
            actions,
            text="Open output folder when finished",
            variable=self.open_folder_var,
            style="Converter.TCheckbutton",
        ).grid(row=0, column=2, sticky="w")

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
        donor_text = self.donor_var.get().strip()
        donor = Path(donor_text) if donor_text and Path(donor_text).is_file() else None

        def work():
            try:
                self.events.put(("log", f"Preflight: {mtu.name}  (Class-C: {profile_key})"))
                self.events.put(("progress", (15, "Reading and decoding MTU...")))
                model = builder.build_model(mtu, profile_key)
                self.events.put(("progress", (75, "Validating recovered model...")))
                known_font_ids = None
                if donor is not None:
                    try:
                        pythoncom, _, _, db = builder.open_dao(donor)
                        try:
                            known_font_ids, _ = builder.donor_font_bindings(
                                db, model["resources"]["Fonts"])
                        finally:
                            db.Close()
                            pythoncom.CoUninitialize()
                    except Exception as error:
                        self.events.put(("log", f"Font comparison unavailable: {error}"))
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
        profile_key = self._profile_key()
        if out.exists() and not messagebox.askyesno(APP_TITLE, f"Overwrite existing file?\n\n{out}"):
            return

        def work():
            try:
                self.events.put(("log", f"Converting: {mtu}"))
                self.events.put(("log", f"Donor:     {donor}"))
                self.events.put(("log", f"Output:    {out}"))
                self.events.put(("log", f"Class-C:   {profile_key}"))
                model, verification = builder.build_ips(
                    mtu, donor, out, project_name, profile_key,
                    lambda percent, status: self.events.put(("progress", (percent, status))),
                )
                cc = mr.reconstruct_class_c_by_profile(
                    model["frames"], model["sign_tables"], model["class_c_profile"]
                )
                verification["class_c_rows"] = len(cc)
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
                elif kind == "progress":
                    percent, status = payload
                    self._set_progress(int(percent), str(status))
                elif kind == "preflight_done":
                    report = payload
                    self._append_log(json.dumps(report, indent=2))
                    self._set_busy(False, "Preflight passed." if report.get("status") == "PASS" else "Preflight failed.")
                    if report.get("status") == "PASS":
                        warnings = report.get("warnings", [])
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
                        messagebox.showinfo(
                            APP_TITLE,
                            "Preflight passed.\n\n"
                            f"Class-C schema: {report.get('class_c_profile')}\n"
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
                  "Route / Destination / SmallSide and expanded five-field Class-C projects."),
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

        ttk.Label(root, text="Class-C schema:").grid(row=6, column=0, sticky="w", padx=(0, 8), pady=5)
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
                self.events.put(("log", f"Preflight: {mtu.name}  (Class-C: {profile_key})"))
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
                self.events.put(("log", f"Class-C:   {profile_key}"))
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
                            f"Class-C schema: {report.get('class_c_profile')}\n"
                            f"Messages: {report.get('message_pairs')}\n"
                            f"Class-C rows: {report.get('class_c_rows')}\n"
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

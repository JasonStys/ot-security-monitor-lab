"""Native offline workbench: real project inputs, analysis, searchable evidence, history and export. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Workbench — line 225
# definition: __init__ — line 228
# parameter: root — line 228
# parameter: self — line 228
# parameter: state — line 228
# attribute: root — line 230
# attribute: state — line 230
# attribute: identity — line 231
# attribute: acceptance_result — line 232
# attribute: worker_thread — line 233
# attribute: busy — line 234
# attribute: closing — line 235
# attribute: selected_run — line 236
# attribute: current — line 237
# attribute: visible — line 238
# attribute: bundle_names — line 239
# attribute: field_widgets — line 240
# attribute: results — line 241
# attribute: values — line 242
# variable: _kind — line 242
# variable: _label — line 242
# variable: name — line 242
# attribute: mode — line 243
# attribute: prepared — line 244
# attribute: authorized — line 245
# attribute: search — line 246
# attribute: view — line 247
# attribute: status — line 248
# variable: style — line 259
# variable: container — line 263
# attribute: tabs — line 272
# variable: _ — line 274
# variable: history — line 274
# variable: inputs — line 274
# variable: results — line 274
# attribute: inputs_page — line 278
# attribute: results_page — line 278
# attribute: controls — line 279
# variable: prepared — line 284
# attribute: operation — line 301
# parameter: _event — line 309
# variable: index — line 310
# variable: kind — line 310
# variable: label — line 310
# variable: name — line 310
# variable: label_widget — line 311
# variable: entry — line 313
# variable: button — line 328
# variable: row — line 336
# attribute: acknowledge — line 337
# attribute: run_button — line 343
# variable: filters — line 348
# attribute: view_box — line 351
# parameter: _event — line 355
# variable: search — line 357
# parameter: _args — line 359
# variable: pane — line 360
# variable: table_frame — line 362
# attribute: table — line 363
# variable: key — line 369
# variable: label — line 369
# variable: width — line 369
# variable: scroll — line 377
# attribute: details — line 383
# attribute: export_button — line 387
# attribute: review_button — line 391
# attribute: review_button — line 393
# attribute: history_table — line 399
# variable: label — line 405
# variable: name — line 405
# variable: width — line 405
# attribute: open_button — line 414
# attribute: remove_button — line 420
# variable: footer — line 426
# attribute: status_label — line 428
# parameter: event — line 432
# attribute: footer_buttons — line 434
# variable: action — line 435
# variable: label — line 435
# variable: padding — line 435
# variable: button — line 440
# variable: variable — line 443
# parameter: _args — line 444
# parameter: _args — line 445
# definition: load_prepared — line 450
# parameter: self — line 450
# variable: selected — line 454
# variable: name — line 456
# variable: variable — line 456
# definition: show_fields — line 465
# parameter: self — line 465
# variable: active — line 467
# variable: name — line 468
# variable: widgets — line 468
# variable: widget — line 469
# definition: input_changed — line 475
# parameter: self — line 475
# definition: review_selected — line 480
# parameter: self — line 480
# definition: choose — line 484
# parameter: kind — line 484
# parameter: name — line 484
# parameter: self — line 484
# variable: value — line 489
# variable: value — line 493
# variable: value — line 499
# definition: run — line 506
# parameter: self — line 506
# variable: name — line 515
# variable: parameters — line 515
# variable: variable — line 515
# variable: selection — line 518
# attribute: busy — line 522
# variable: control — line 525
# attribute: worker_thread — line 530
# definition: worker — line 538
# parameter: parameters — line 538
# parameter: self — line 538
# variable: directory — line 543
# variable: files — line 544
# variable: kind — line 544
# variable: summary — line 544
# variable: identity — line 547
# definition: poll — line 566
# parameter: self — line 566
# variable: identity — line 569
# variable: summary — line 569
# attribute: busy — line 570
# variable: control — line 573
# definition: show — line 592
# parameter: identity — line 592
# parameter: self — line 592
# variable: files — line 594
# attribute: current — line 595
# attribute: bundle_names — line 596
# attribute: selected_run — line 597
# definition: render — line 604
# parameter: self — line 604
# variable: query — line 607
# variable: matching — line 608
# variable: row — line 610
# attribute: visible — line 613
# variable: index — line 614
# variable: row — line 614
# definition: detail_text — line 620
# parameter: self — line 620
# parameter: value — line 620
# definition: inspect — line 627
# parameter: _event — line 627
# parameter: self — line 627
# variable: selected — line 629
# definition: refresh_history — line 635
# parameter: self — line 635
# variable: row — line 638
# definition: open_history — line 646
# parameter: self — line 646
# variable: selected — line 650
# definition: export — line 660
# parameter: self — line 660
# variable: parent — line 665
# definition: remove_history — line 680
# parameter: self — line 680
# variable: selected — line 687
# variable: identity — line 694
# variable: files — line 695
# variable: expected — line 696
# variable: data — line 700
# variable: name — line 700
# attribute: selected_run — line 712
# attribute: current — line 713
# attribute: bundle_names — line 714
# definition: help — line 727
# parameter: self — line 727
# definition: licenses — line 736
# parameter: self — line 736
# variable: name — line 739
# variable: text — line 740
# variable: dialog — line 741
# variable: frame — line 744
# variable: label — line 746
# variable: area — line 752
# variable: scroll — line 753
# definition: exit — line 767
# parameter: self — line 767
# attribute: closing — line 769
# definition: main — line 775
# parameter: argv — line 775
# variable: parser — line 777
# variable: args — line 781
# variable: state — line 786
# variable: window — line 787
# variable: root — line 788
# variable: identity — line 790
# attribute: acceptance_output — line 804
# variable: state — line 812
# variable: root — line 818
# variable: window — line 819
# attribute: identity — line 820
# END CODE MAP

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import queue
import sqlite3
import sys
import tempfile
import threading
import tkinter as tk
from functools import partial
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from . import desktop_project as project
from .desktop_io import Rejected, canonical, read_bytes
from .desktop_state import Workspace, package_identity, profile_path, unlinked


class Workbench:
    """One actual Tk application around the existing core; background jobs never update widgets off-thread."""

    def __init__(self, root: tk.Tk, state: Workspace) -> None:
        """Build real project-specific controls; inputs are never executed as commands or plugins."""
        self.root, self.state = root, state
        self.identity: dict[str, Any] = {}
        self.acceptance_result: bool | None = None
        self.worker_thread: threading.Thread | None = None
        self.busy = False
        self.closing = False
        self.selected_run = 0
        self.current: dict[str, list[dict[str, Any]]] = {}
        self.visible: list[dict[str, Any]] = []
        self.bundle_names: set[str] = set()
        self.field_widgets: dict[str, list[ttk.Widget]] = {}
        self.results: queue.Queue[tuple[int | None, str]] = queue.Queue(maxsize=1)
        self.values = {name: tk.StringVar() for name, _label, _kind in project.FIELDS}
        self.mode = tk.StringVar(value=project.MODES[0])
        self.prepared = tk.StringVar(value=project.SCENARIOS[0])
        self.authorized = tk.BooleanVar(value=False)
        self.search = tk.StringVar()
        self.view = tk.StringVar()
        self.status = tk.StringVar(
            value="Choose a prepared scenario or your supported authorized files, then run analysis."
        )
        root.title(project.TITLE + " · Jason Stys")
        if getattr(sys, "frozen", False):
            root.tk.call(
                "wm", "iconbitmap", str(root), "-default", str(project.ROOT / "app.ico")
            )
        root.geometry("1260x860")
        root.minsize(980, 700)
        root.protocol("WM_DELETE_WINDOW", self.exit)
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10))
        style.configure("Treeview", rowheight=28)
        container = ttk.Frame(root, padding=16)
        container.pack(fill="both", expand=True)
        ttk.Label(container, text=project.TITLE, font=("Segoe UI", 21, "bold")).pack(
            anchor="w"
        )
        ttk.Label(
            container,
            text=f"Version {project.VERSION} · Created by Jason Stys · Offline evidence, human review · No host changes or background uploads",
        ).pack(anchor="w", pady=(4, 12))
        self.tabs = ttk.Notebook(container)
        self.tabs.pack(fill="both", expand=True)
        inputs, results, history = (ttk.Frame(self.tabs, padding=14) for _ in range(3))
        self.tabs.add(inputs, text="1  Inputs and analysis")
        self.tabs.add(results, text="2  Findings and timeline")
        self.tabs.add(history, text="3  Saved analyses")
        self.inputs_page, self.results_page = inputs, results
        self.controls: list[ttk.Widget] = []
        ttk.Label(
            inputs,
            text="Prepared scenarios are optional inputs in this same application; they are not live host data.",
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=8)
        prepared = ttk.Combobox(
            inputs,
            textvariable=self.prepared,
            values=project.SCENARIOS,
            state="readonly",
            width=50,
        )
        prepared.grid(row=1, column=0, sticky="ew")
        self.controls.append(
            ttk.Button(
                inputs, text="Load prepared scenario", command=self.load_prepared
            )
        )
        self.controls[-1].grid(row=1, column=1, sticky="w", padx=8)
        ttk.Label(inputs, text="Operation").grid(
            row=2, column=0, sticky="w", pady=(15, 4)
        )
        self.operation = ttk.Combobox(
            inputs,
            textvariable=self.mode,
            values=project.MODES,
            state="readonly",
            width=50,
        )
        self.operation.grid(row=2, column=1, columnspan=2, sticky="ew", pady=(15, 4))
        self.operation.bind("<<ComboboxSelected>>", lambda _event: self.show_fields())
        for index, (name, label, kind) in enumerate(project.FIELDS, 3):
            label_widget = ttk.Label(inputs, text=label, wraplength=380, justify="left")
            label_widget.grid(row=index, column=0, sticky="w", pady=4)
            entry = (
                ttk.Combobox(
                    inputs,
                    textvariable=self.values[name],
                    values=project.CHOICES[name],
                    state="readonly",
                    width=42,
                )
                if name in project.CHOICES
                else ttk.Entry(inputs, textvariable=self.values[name], width=42)
            )
            entry.grid(row=index, column=1, sticky="ew", pady=4)
            self.field_widgets[name] = [label_widget, entry]
            self.controls.append(entry)
            if kind not in ("text", "choice"):
                button = ttk.Button(
                    inputs,
                    text="Choose…",
                    command=partial(self.choose, name, kind),
                )
                button.grid(row=index, column=2, padx=8)
                self.controls.append(button)
                self.field_widgets[name].append(button)
        row = len(project.FIELDS) + 3
        self.acknowledge = ttk.Checkbutton(
            inputs,
            text="I am permitted to use these files. Local state and exports can contain sensitive evidence.",
            variable=self.authorized,
        )
        self.acknowledge.grid(row=row, column=0, columnspan=3, sticky="w", pady=12)
        self.run_button = ttk.Button(
            inputs, text="Run selected analysis", command=self.run
        )
        self.run_button.grid(row=row + 1, column=0, sticky="w", pady=8)
        inputs.columnconfigure(1, weight=1)
        filters = ttk.Frame(results)
        filters.pack(fill="x", pady=(0, 8))
        ttk.Label(filters, text="Evidence view").pack(side="left")
        self.view_box = ttk.Combobox(
            filters, textvariable=self.view, state="readonly", width=32
        )
        self.view_box.pack(side="left", padx=8)
        self.view_box.bind("<<ComboboxSelected>>", lambda _event: self.render())
        ttk.Label(filters, text="Search literal evidence").pack(side="left")
        search = ttk.Entry(filters, textvariable=self.search)
        search.pack(side="left", fill="x", expand=True, padx=8)
        self.search.trace_add("write", lambda *_args: self.render())
        pane = ttk.Panedwindow(results, orient="vertical")
        pane.pack(fill="both", expand=True)
        table_frame = ttk.Frame(pane)
        self.table = ttk.Treeview(
            table_frame,
            columns=("time", "detector", "event", "state"),
            show="headings",
            selectmode="browse",
        )
        for key, label, width in (
            ("time", project.COLUMNS[0], 220),
            ("detector", project.COLUMNS[1], 280),
            ("event", project.COLUMNS[2], 250),
            ("state", project.COLUMNS[3], 190),
        ):
            self.table.heading(key, text=label)
            self.table.column(key, width=width, minwidth=80)
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.table.bind("<<TreeviewSelect>>", self.inspect)
        pane.add(table_frame, weight=3)
        self.details = tk.Text(
            pane, height=12, wrap="word", state="disabled", font=("Consolas", 10)
        )
        pane.add(self.details, weight=2)
        self.export_button = ttk.Button(
            results, text="Export selected analysis bundle…", command=self.export
        )
        self.export_button.pack(before=pane, side="bottom", anchor="w", pady=8)
        self.review_button = None
        if project.REVIEW_MODE is not None:
            self.review_button = ttk.Button(
                results, text="Review selected resource…", command=self.review_selected
            )
            self.review_button.pack(
                before=self.export_button, side="bottom", anchor="w", pady=4
            )
        self.history_table = ttk.Treeview(
            history,
            columns=("id", "created", "kind", "summary"),
            show="headings",
            selectmode="browse",
        )
        for name, label, width in (
            ("id", "Analysis", 70),
            ("created", "Created UTC", 210),
            ("kind", "Operation", 190),
            ("summary", "Evidence summary", 410),
        ):
            self.history_table.heading(name, text=label)
            self.history_table.column(name, width=width)
        self.history_table.pack(fill="both", expand=True)
        self.open_button = ttk.Button(
            history, text="Open saved analysis", command=self.open_history
        )
        self.open_button.pack(
            before=self.history_table, side="bottom", anchor="w", pady=8
        )
        self.remove_button = ttk.Button(
            history, text="Remove selected local analysis…", command=self.remove_history
        )
        self.remove_button.pack(
            before=self.open_button, side="bottom", anchor="w", pady=4
        )
        footer = ttk.Frame(container)
        footer.pack(before=self.tabs, side="bottom", fill="x", pady=(10, 0))
        self.status_label = ttk.Label(footer, textvariable=self.status, width=1)
        self.status_label.pack(side="left", fill="x", expand=True)
        self.status_label.bind(
            "<Configure>",
            lambda event: self.status_label.configure(wraplength=max(120, event.width)),
        )
        self.footer_buttons: dict[str, ttk.Button] = {}
        for label, action, padding in (
            ("Help", self.help, 8),
            ("Licenses", self.licenses, 4),
            ("Exit application", self.exit, 0),
        ):
            button = ttk.Button(footer, text=label, command=action)
            button.pack(side="right", padx=padding)
            self.footer_buttons[label] = button
        for variable in self.values.values():
            variable.trace_add("write", lambda *_args: self.authorized.set(False))
        self.mode.trace_add("write", lambda *_args: self.input_changed())
        self.refresh_history()
        self.load_prepared()
        root.after(60, self.poll)

    def load_prepared(self) -> None:
        """Fill actual input controls with bundled fictional examples without running an analysis automatically."""
        if self.busy:
            return
        selected = project.scenario(self.prepared.get())
        self.mode.set(selected["mode"])
        for name, variable in self.values.items():
            variable.set(selected.get(name, ""))
        self.show_fields()
        self.authorized.set(False)
        self.status.set(
            "Fictional scenario prepared. Review its inputs and acknowledge permission before running."
        )
        self.tabs.tk.call(str(self.tabs), "select", str(self.inputs_page))

    def show_fields(self) -> None:
        """Show only settings used by the selected real project operation, without erasing prior input choices."""
        active = set(project.ACTIVE_FIELDS.get(self.mode.get(), ()))
        for name, widgets in self.field_widgets.items():
            for widget in widgets:
                if name in active:
                    widget.grid()
                else:
                    widget.grid_remove()

    def input_changed(self) -> None:
        """Reset acknowledgement and relevant visible fields after a mode edit; this is not authentication."""
        self.authorized.set(False)
        self.show_fields()

    def review_selected(self) -> None:
        """This offline inspector records no approvals or authenticated review identities."""
        return

    def choose(self, name: str, kind: str) -> None:
        """Choose only local supported input paths; nothing is collected, opened as code or uploaded."""
        if self.busy:
            return
        if kind == "directory":
            value = filedialog.askdirectory(
                parent=self.root, title="Choose reviewed input directory"
            )
        elif kind == "files":
            value = "\n".join(
                filedialog.askopenfilenames(
                    parent=self.root, title="Choose authorized snapshots"
                )
            )
        else:
            value = filedialog.askopenfilename(
                parent=self.root, title="Choose supported authorized input"
            )
        if value:
            self.values[name].set(value)
            self.authorized.set(False)

    def run(self) -> None:
        """Capture controls once and start one bounded core operation without blocking the native message loop."""
        if self.busy or self.closing:
            return
        if not self.authorized.get():
            self.status.set(
                "Permission acknowledgement is required; no analysis was started."
            )
            return
        parameters = {name: variable.get() for name, variable in self.values.items()}
        parameters["mode"] = self.mode.get()
        parameters["_run"] = str(self.selected_run)
        selection = self.table.selection()
        parameters["_row"] = (
            canonical(self.visible[int(selection[0])]).decode() if selection else "null"
        )
        self.busy = True
        self.run_button.state(["disabled"])
        self.operation.state(["disabled"])
        for control in self.controls:
            control.state(["disabled"])
        self.status.set(
            "Analysis running offline. Exit waits for the current transaction; inputs are not executed as commands."
        )
        self.worker_thread = threading.Thread(
            target=self.worker,
            args=(parameters,),
            name="owned-offline-analysis",
            daemon=False,
        )
        self.worker_thread.start()

    def worker(self, parameters: dict[str, str]) -> None:
        """Run actual project analysis and atomically retain only completed bounded bundles; never touch widgets."""
        try:
            with tempfile.TemporaryDirectory(
                prefix="owned-analysis-", dir=self.state.path
            ) as directory:
                kind, summary, files = project.analyze(
                    self.state, parameters, Path(directory)
                )
                identity = self.state.save(kind, summary, parameters, files)
            self.results.put((identity, summary))
        except Rejected as error:
            self.results.put(
                (
                    None,
                    "Input/output rejected: "
                    + str(error)[:200]
                    + ". Earlier saved analyses were retained.",
                )
            )
        except Exception:
            self.results.put(
                (
                    None,
                    "Input/output rejected. Check supported contracts, required fields, selected evidence and history capacity; existing analyses were retained.",
                )
            )

    def poll(self) -> None:
        """Receive a completed worker on the Tk thread; never destroy the application while a write is in flight."""
        try:
            identity, summary = self.results.get_nowait()
            self.busy = False
            self.run_button.state(["!disabled"])
            self.operation.state(["!disabled", "readonly"])
            for control in self.controls:
                control.state(["!disabled"])
            try:
                if identity is not None:
                    self.show(identity)
                    self.refresh_history()
                self.status.set(summary)
            except (Rejected, sqlite3.Error, ValueError, KeyError, TypeError):
                self.status.set(
                    "Saved evidence could not be rendered; retain your private backup. No files were reset."
                )
        except queue.Empty:
            pass
        if self.closing and not self.busy:
            self.state.close()
            self.root.destroy()
            return
        self.root.after(60, self.poll)

    def show(self, identity: int) -> None:
        """Open one verified actual saved bundle; no source is re-evaluated or silently replaced on reopen."""
        files = self.state.files(identity)
        self.current = project.views(files)
        self.bundle_names = set(files)
        self.selected_run = identity
        self.view_box.configure(values=tuple(self.current))
        self.view.set(next(iter(self.current)))
        self.search.set("")
        self.render()
        self.tabs.tk.call(str(self.tabs), "select", str(self.results_page))

    def render(self) -> None:
        """Filter literal evidence and bound visible rows; full original output remains exportable."""
        self.table.delete(*self.table.get_children())
        query = self.search.get().casefold().strip()
        matching = [
            row
            for row in self.current.get(self.view.get(), [])
            if not query or query in json.dumps(row, ensure_ascii=False).casefold()
        ]
        self.visible = matching[:5000]
        for index, row in enumerate(self.visible):
            self.table.insert("", "end", iid=str(index), values=project.cells(row))
        self.detail_text(
            f"{len(self.visible)} shown / {len(matching)} matching records. At most 5,000 rows are rendered; full evidence is retained in the private bundle."
        )

    def detail_text(self, value: str) -> None:
        """Show copyable literal evidence in a read-only text area; no markup is evaluated."""
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", value)
        self.details.configure(state="disabled")

    def inspect(self, _event: Any = None) -> None:
        """Display the exact selected record and its uncertainty/context without creating an incident verdict."""
        selected = self.table.selection()
        if selected:
            self.detail_text(
                json.dumps(self.visible[int(selected[0])], indent=2, ensure_ascii=False)
            )

    def refresh_history(self) -> None:
        """List existing analysis identities without running a fixture or contacting a host."""
        self.history_table.delete(*self.history_table.get_children())
        for row in self.state.history():
            self.history_table.insert(
                "",
                "end",
                iid=str(row["id"]),
                values=(row["id"], row["created"], row["kind"], row["summary"]),
            )

    def open_history(self) -> None:
        """Reopen only a selected retained analysis; busy operations cannot be replaced halfway through."""
        if self.busy:
            return
        selected = self.history_table.selection()
        if selected:
            try:
                self.show(int(selected[0]))
                self.status.set("Saved evidence reopened without re-running analysis.")
            except (Rejected, sqlite3.Error, ValueError, KeyError):
                self.status.set(
                    "Saved evidence could not be verified; no files were reset."
                )

    def export(self) -> None:
        """Export an exact verified bundle into a new directory under a user-selected private parent."""
        if self.busy or not self.selected_run:
            self.status.set("Select a completed saved analysis before exporting.")
            return
        parent = filedialog.askdirectory(
            parent=self.root,
            title="Choose private export parent; a new directory will be created",
        )
        if parent:
            try:
                self.state.export(self.selected_run, Path(parent), project.PRODUCT)
                self.status.set(
                    "Verified bundle exported to a new directory in the selected parent. Review private evidence before sharing."
                )
            except (Rejected, OSError, sqlite3.Error):
                self.status.set(
                    "Export unavailable. Existing evidence was retained; inspect any newly created partial export."
                )

    def remove_history(self) -> None:
        """Remove one confirmed exact private local copy; never delete original inputs or exported directories."""
        if self.busy:
            self.status.set(
                "Wait for the active analysis before changing history retention."
            )
            return
        selected = self.history_table.selection()
        if not selected:
            self.status.set(
                "Select a saved analysis in History before removing its local copy."
            )
            return
        try:
            identity = int(selected[0])
            files = self.state.files(identity)
            expected = hashlib.sha256(
                canonical(
                    {
                        name: hashlib.sha256(data).hexdigest()
                        for name, data in files.items()
                    }
                )
            ).hexdigest()
            if not messagebox.askyesno(
                "Remove local saved analysis?",
                "Export a private backup first if you need to retain this evidence. Remove only this selected local analysis? Original input files and previously exported copies are not deleted.",
                parent=self.root,
            ):
                return
            self.state.remove(identity, expected)
            if self.selected_run == identity:
                self.selected_run = 0
                self.current = {}
                self.bundle_names = set()
                self.view_box.configure(values=())
                self.view.set("")
                self.render()
            self.refresh_history()
            self.status.set(
                "Selected local analysis removed. Original inputs and exported copies were not changed."
            )
        except (Rejected, sqlite3.Error, ValueError):
            self.status.set(
                "Selected evidence changed or could not be verified; nothing was removed."
            )

    def help(self) -> None:
        """Explain purpose, controls and plaintext-owner boundaries without external content or popups from third parties."""
        messagebox.showinfo(
            project.TITLE + " — Help",
            project.HELP
            + "\n\nChoose Inputs → operation/files → permission → Run. Findings are searchable literal evidence; select a row to inspect. Saved analyses reopens exact bundles; Export creates a new private directory. Exit waits for an active analysis. Up to 20 runs / 128 MiB of retained bundle payloads (database/metadata add overhead), 64 MiB per bundle / 32 MiB per file. Export backups and explicitly remove local analyses to manage retention; no automatic eviction. Back up the entire profile only after clean exit. Created by Jason Stys: github.com/JasonStys · linkedin.com/in/jason-stys-31b30b351",
            parent=self.root,
        )

    def licenses(self) -> None:
        """Offer readable bundled runtime notices locally without opening a browser or exposing data paths."""
        try:
            name = "notices.txt" if getattr(sys, "frozen", False) else "LICENSE"
            text = read_bytes(project.ROOT / name, 8 * 1024 * 1024).decode("utf-8")
            dialog = tk.Toplevel(self.root)
            dialog.title(project.TITLE + " — Licenses")
            dialog.geometry("850x620")
            frame = ttk.Frame(dialog, padding=12)
            frame.pack(fill="both", expand=True)
            label = (
                "Bundled application and runtime notices"
                if name == "notices.txt"
                else "Authored source license; portable packages also include runtime notices"
            )
            ttk.Label(frame, text=label).pack(anchor="w", pady=8)
            area = tk.Text(frame, wrap="word", font=("Consolas", 10))
            scroll = ttk.Scrollbar(frame, command=area.yview)
            area.configure(yscrollcommand=scroll.set)
            scroll.pack(side="right", fill="y")
            area.pack(fill="both", expand=True)
            area.insert("1.0", text)
            area.configure(state="disabled")
            ttk.Button(frame, text="Close licenses", command=dialog.destroy).pack(
                anchor="e", pady=8
            )
        except (Rejected, UnicodeError, tk.TclError):
            self.status.set(
                "License text could not be read; verify the portable package before use."
            )

    def exit(self) -> None:
        """Wait for the owned worker and committed evidence rather than interrupting a write or killing another process."""
        self.closing = True
        self.status.set(
            "Closing after the owned analysis finishes. Saved evidence remains on this PC."
        )


def main(argv: list[str] | None = None) -> int:
    """Open the actual offline native workbench; special acceptance requires an explicit synthetic profile."""
    parser = argparse.ArgumentParser(description=project.TITLE + " · Jason Stys")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--acceptance-output", type=Path)
    parser.add_argument("--acceptance-reopen", action="store_true")
    args = parser.parse_args(argv)
    if args.acceptance_output and not args.profile:
        parser.error("acceptance requires an explicit synthetic profile")
    if args.acceptance_reopen and not args.acceptance_output:
        parser.error("acceptance reopen requires the explicit acceptance mode")
    state = None
    window = None
    root = None
    try:
        identity = package_identity(
            project.ROOT,
            project.PRODUCT,
            project.VERSION,
            project.RESOURCES,
            project.RESOURCE_LIMITS,
        )
        if (
            args.acceptance_output
            and not args.acceptance_reopen
            and args.profile.exists()
        ):
            raise Rejected("acceptance requires a new synthetic profile")
        if args.acceptance_output:
            args.acceptance_output = unlinked(args.acceptance_output)
            if (
                args.acceptance_output.exists()
                or not args.acceptance_output.parent.is_dir()
            ):
                raise Rejected(
                    "acceptance output must be new under an existing unlinked parent"
                )
        state = Workspace(
            args.profile or profile_path(project.PROFILE),
            project.PRODUCT,
            project.ROOT,
            synthetic=bool(args.acceptance_output),
        )
        root = tk.Tk()
        window = Workbench(root, state)
        window.identity = identity
        if args.acceptance_output:
            from scripts.native_acceptance import exercise

            root.after(
                100,
                lambda: exercise(
                    window, args.acceptance_output, args.acceptance_reopen
                ),
            )
        root.mainloop()
        return (
            0 if not args.acceptance_output or window.acceptance_result is True else 2
        )
    except (Rejected, OSError, sqlite3.Error, tk.TclError):
        if not args.acceptance_output:
            with contextlib.suppress(tk.TclError):
                messagebox.showerror(
                    project.TITLE,
                    "The local workspace could not start. Close an existing instance or review profile permissions. No saved evidence was reset.",
                )
        return 2
    finally:
        if window and window.worker_thread:
            window.worker_thread.join()
        if state:
            state.close()
        if root:
            with contextlib.suppress(tk.TclError):
                root.destroy()


if __name__ == "__main__":
    raise SystemExit(main())

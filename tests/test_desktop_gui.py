"""Presentation-adapter unit tests with real core/SQLite workers; real widgets are separately frozen-tested. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Variable — line 230
# definition: __init__ — line 233
# parameter: self — line 233
# parameter: value — line 233
# attribute: callbacks — line 235
# attribute: value — line 235
# definition: get — line 237
# parameter: self — line 237
# definition: set — line 241
# parameter: self — line 241
# parameter: value — line 241
# attribute: value — line 243
# variable: callback — line 244
# definition: trace_add — line 247
# parameter: _event — line 247
# parameter: callback — line 247
# parameter: self — line 247
# definition: Widget — line 252
# definition: __init__ — line 255
# parameter: _args — line 255
# parameter: kwargs — line 255
# parameter: self — line 255
# attribute: options — line 257
# attribute: rows — line 257
# attribute: selected — line 257
# attribute: flags — line 258
# attribute: tk — line 259
# parameter: _items — line 259
# definition: pack — line 261
# parameter: _kwargs — line 261
# parameter: self — line 261
# definition: grid — line 264
# parameter: _kwargs — line 264
# parameter: self — line 264
# definition: grid_remove — line 267
# parameter: self — line 267
# definition: columnconfigure — line 270
# parameter: _args — line 270
# parameter: _kwargs — line 270
# parameter: self — line 270
# definition: add — line 273
# parameter: _args — line 273
# parameter: _kwargs — line 273
# parameter: self — line 273
# definition: theme_use — line 276
# parameter: _args — line 276
# parameter: self — line 276
# definition: configure — line 279
# parameter: _args — line 279
# parameter: kwargs — line 279
# parameter: self — line 279
# definition: heading — line 283
# parameter: _args — line 283
# parameter: _kwargs — line 283
# parameter: self — line 283
# definition: column — line 286
# parameter: _args — line 286
# parameter: _kwargs — line 286
# parameter: self — line 286
# definition: bind — line 289
# parameter: _args — line 289
# parameter: self — line 289
# definition: yview — line 292
# parameter: _args — line 292
# parameter: self — line 292
# definition: set — line 295
# parameter: _args — line 295
# parameter: self — line 295
# definition: state — line 298
# parameter: flags — line 298
# parameter: self — line 298
# variable: flag — line 300
# definition: invoke — line 306
# parameter: self — line 306
# definition: insert — line 312
# parameter: _parent — line 312
# parameter: _position — line 312
# parameter: iid — line 312
# parameter: self — line 312
# parameter: values — line 312
# definition: delete — line 316
# parameter: items — line 316
# parameter: self — line 316
# variable: item — line 318
# attribute: selected — line 320
# variable: item — line 320
# definition: get_children — line 322
# parameter: self — line 322
# definition: selection — line 326
# parameter: self — line 326
# definition: selection_set — line 330
# parameter: identity — line 330
# parameter: self — line 330
# attribute: selected — line 333
# definition: Text — line 336
# definition: delete — line 339
# parameter: _args — line 339
# parameter: self — line 339
# attribute: text — line 341
# definition: insert — line 343
# parameter: _position — line 343
# parameter: self — line 343
# parameter: text — line 343
# attribute: text — line 345
# definition: Root — line 348
# definition: __init__ — line 351
# parameter: self — line 351
# attribute: callbacks — line 353
# attribute: destroyed — line 353
# attribute: on_loop — line 354
# definition: title — line 356
# parameter: _args — line 356
# parameter: self — line 356
# definition: geometry — line 359
# parameter: _args — line 359
# parameter: self — line 359
# definition: minsize — line 362
# parameter: _args — line 362
# parameter: self — line 362
# definition: protocol — line 365
# parameter: _event — line 365
# parameter: callback — line 365
# parameter: self — line 365
# attribute: close_callback — line 367
# definition: after — line 369
# parameter: _delay — line 369
# parameter: callback — line 369
# parameter: self — line 369
# definition: destroy — line 373
# parameter: self — line 373
# attribute: destroyed — line 375
# definition: mainloop — line 377
# parameter: self — line 377
# variable: _ — line 381
# definition: presentation — line 389
# parameter: monkeypatch — line 389
# parameter: _parent — line 394
# variable: name — line 396
# variable: messages — line 410
# parameter: _kwargs — line 412
# parameter: args — line 412
# parameter: _kwargs — line 415
# parameter: args — line 415
# definition: app — line 421
# parameter: presentation — line 421
# parameter: tmp_path — line 421
# variable: state — line 423
# variable: root — line 424
# variable: window — line 425
# definition: settle — line 439
# parameter: window — line 439
# variable: deadline — line 441
# definition: test_real_controller_run_filter_detail_history_export_and_help — line 448
# parameter: app — line 449
# parameter: monkeypatch — line 449
# parameter: presentation — line 449
# parameter: tmp_path — line 449
# parameter: _kwargs — line 475
# variable: original — line 477
# variable: exported — line 479
# variable: path — line 480
# parameter: _kwargs — line 485
# definition: test_explicit_retention_confirmation_removes_only_selected_local_copy — line 491
# parameter: app — line 492
# parameter: monkeypatch — line 492
# parameter: tmp_path — line 492
# variable: exported — line 502
# variable: original — line 503
# parameter: _args — line 504
# parameter: _kwargs — line 504
# parameter: _args — line 507
# parameter: _kwargs — line 507
# variable: path — line 510
# attribute: busy — line 511
# attribute: busy — line 514
# definition: test_input_selection_cancel_busy_failure_and_literal_row_cap — line 517
# parameter: app — line 518
# parameter: monkeypatch — line 518
# parameter: tmp_path — line 518
# variable: name — line 521
# parameter: _kwargs — line 525
# parameter: _kwargs — line 530
# parameter: _kwargs — line 533
# variable: kind — line 535
# variable: value — line 539
# parameter: _kwargs — line 540
# attribute: busy — line 543
# attribute: busy — line 549
# attribute: current — line 556
# variable: index — line 559
# definition: test_close_retains_lock_until_actual_core_transaction_finishes — line 573
# parameter: app — line 574
# parameter: monkeypatch — line 574
# parameter: tmp_path — line 574
# variable: ready — line 577
# variable: release — line 577
# variable: actual — line 578
# definition: pause — line 580
# parameter: args — line 580
# variable: reopened — line 598
# definition: test_main_native_close_and_rejected_acceptance_paths — line 605
# parameter: monkeypatch — line 606
# parameter: presentation — line 606
# parameter: tmp_path — line 606
# variable: actual — line 609
# definition: create — line 611
# parameter: root — line 611
# parameter: state — line 611
# variable: window — line 613
# attribute: on_loop — line 614
# variable: profile — line 618
# variable: reopened — line 620
# variable: unknown — line 644
# END CODE MAP

import threading
import time
from types import SimpleNamespace

import pytest

from otmon import desktop as module
from otmon import desktop_project as project
from otmon.desktop_io import Rejected
from otmon.desktop_state import Workspace


class Variable:
    """Inert presentation variable; invokes the same registered GUI trace callbacks."""

    def __init__(self, value=""):
        """Keep a scalar control value and registered change callbacks."""
        self.value, self.callbacks = value, []

    def get(self):
        """Return the current presentation control value."""
        return self.value

    def set(self, value):
        """Change a control and exercise actual application rendering callbacks."""
        self.value = value
        for callback in self.callbacks:
            callback()

    def trace_add(self, _event, callback):
        """Retain the GUI's value-change handler."""
        self.callbacks.append(callback)


class Widget:
    """Minimal inert ttk presentation adapter; no core, storage or analysis output is mocked."""

    def __init__(self, *_args, **kwargs):
        """Retain properties, rows and command closures."""
        self.options, self.rows, self.selected = kwargs, {}, ()
        self.flags = set()
        self.tk = SimpleNamespace(call=lambda *_items: None)

    def pack(self, **_kwargs):
        """Accept presentation layout."""

    def grid(self, **_kwargs):
        """Accept presentation grid coordinates."""

    def grid_remove(self):
        """Accept operation-specific hidden controls."""

    def columnconfigure(self, *_args, **_kwargs):
        """Accept resize weights."""

    def add(self, *_args, **_kwargs):
        """Accept notebook/paned-window children."""

    def theme_use(self, *_args):
        """Accept native style selection."""

    def configure(self, *_args, **kwargs):
        """Retain updated widget options."""
        self.options.update(kwargs)

    def heading(self, *_args, **_kwargs):
        """Accept a literal table heading."""

    def column(self, *_args, **_kwargs):
        """Accept table sizing."""

    def bind(self, *_args):
        """Accept event registration; tests invoke actual handlers explicitly."""

    def yview(self, *_args):
        """Accept scroll requests."""

    def set(self, *_args):
        """Accept scrollbar position updates."""

    def state(self, flags):
        """Preserve disabled controls so a simulated click cannot bypass a busy guard."""
        for flag in flags:
            if flag.startswith("!"):
                self.flags.discard(flag[1:])
            else:
                self.flags.add(flag)

    def invoke(self):
        """Invoke the actual registered command unless the control is disabled."""
        if "disabled" not in self.flags:
            return self.options["command"]()
        return None

    def insert(self, _parent, _position, *, iid, values):
        """Retain exact rows inserted by real project rendering."""
        self.rows[iid] = values

    def delete(self, *items):
        """Remove rows and their selections like a real treeview."""
        for item in items:
            self.rows.pop(item, None)
        self.selected = tuple(item for item in self.selected if item in self.rows)

    def get_children(self):
        """Return displayed row identities."""
        return tuple(self.rows)

    def selection(self):
        """Return the current selected row identity."""
        return self.selected

    def selection_set(self, identity):
        """Select one existing row like a real single-selection control."""
        assert identity in self.rows
        self.selected = (identity,)


class Text(Widget):
    """Retain literal detail output without interpreting markup or executing event fields."""

    def delete(self, *_args):
        """Clear existing literal detail text."""
        self.text = ""

    def insert(self, _position, text):
        """Retain the exact rendered detail text."""
        self.text = text


class Root:
    """Deterministic presentation event queue; actual Tk mainloops are independently exercised by frozen acceptance."""

    def __init__(self):
        """Create a fresh owned presentation root."""
        self.callbacks, self.destroyed = [], False
        self.on_loop = None

    def title(self, *_args):
        """Accept window title."""

    def geometry(self, *_args):
        """Accept initial geometry."""

    def minsize(self, *_args):
        """Accept minimum geometry."""

    def protocol(self, _event, callback):
        """Keep the application's native close callback."""
        self.close_callback = callback

    def after(self, _delay, callback):
        """Queue the actual lifecycle callback without a platform display server."""
        self.callbacks.append(callback)

    def destroy(self):
        """Mark only this owned root as closed."""
        self.destroyed = True

    def mainloop(self):
        """Run the requested test lifecycle using real application callbacks."""
        if self.on_loop:
            self.on_loop()
        for _ in range(200):
            if self.destroyed:
                return
            self.callbacks.pop(0)()
        raise AssertionError("presentation lifecycle did not close")


@pytest.fixture
def presentation(monkeypatch):
    """Replace only OS presentation surfaces; real worker, core, SQLite and export code remain active."""
    monkeypatch.setattr(module.tk, "StringVar", Variable)
    monkeypatch.setattr(module.tk, "BooleanVar", Variable)
    monkeypatch.setattr(module.tk, "Tk", Root)
    monkeypatch.setattr(module.tk, "Toplevel", lambda _parent: Root())
    monkeypatch.setattr(module.tk, "Text", Text)
    for name in (
        "Frame",
        "Label",
        "Notebook",
        "Combobox",
        "Entry",
        "Button",
        "Checkbutton",
        "Panedwindow",
        "Treeview",
        "Scrollbar",
        "Style",
    ):
        monkeypatch.setattr(module.ttk, name, Widget)
    messages = []
    monkeypatch.setattr(
        module.messagebox, "showinfo", lambda *args, **_kwargs: messages.append(args)
    )
    monkeypatch.setattr(
        module.messagebox, "showerror", lambda *args, **_kwargs: messages.append(args)
    )
    return messages


@pytest.fixture
def app(tmp_path, presentation):
    """Build the actual workbench controller against an isolated real durable workspace."""
    state = Workspace(tmp_path / "profile", project.PRODUCT, project.ROOT)
    root = Root()
    window = module.Workbench(root, state)
    # Presentation tests exercise the real offline domain engine and SQLite;
    # actual widgets/mainloop are separately proved by the final frozen consumer.
    window.prepared.set(project.SCENARIOS[1])
    window.load_prepared()
    try:
        yield window
    finally:
        if window.worker_thread:
            window.worker_thread.join(10)
            assert not window.worker_thread.is_alive()
        state.close()


def settle(window):
    """Observe completion of one actual owned analysis; no retries or invented report values."""
    deadline = time.monotonic() + 10
    while window.busy and time.monotonic() < deadline:
        window.poll()
        time.sleep(0.005)
    assert not window.busy


def test_real_controller_run_filter_detail_history_export_and_help(
    app, tmp_path, monkeypatch, presentation
):
    """Real core results drive controls, literal filters, exact private exports and history reopening."""
    app.export()
    assert "completed" in app.status.get()
    app.run_button.invoke()
    assert not app.busy and app.state.history() == []
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    assert app.selected_run == 1 and len(app.state.history()) == 1
    assert len(app.table.get_children()) > 0
    app.table.selection_set("0")
    app.inspect()
    assert "{" in app.details.text
    app.review_selected()
    if project.REVIEW_MODE is not None:
        assert app.mode.get() == project.REVIEW_MODE and app.authorized.get() is False
    app.search.set("not-a-supported-record-never-present")
    assert app.table.get_children() == ()
    app.inspect()
    app.search.set("")
    app.history_table.selection_set("1")
    app.open_button.invoke()
    assert "without re-running" in app.status.get()
    monkeypatch.setattr(
        module.filedialog, "askdirectory", lambda **_kwargs: str(tmp_path)
    )
    original = app.state.files(1)
    app.export_button.invoke()
    exported = next(tmp_path.glob(project.PRODUCT + "-run-*"))
    assert {path.name: path.read_bytes() for path in exported.iterdir()} == original
    app.help()
    assert "plaintext" in presentation[-1][1]
    app.licenses()
    monkeypatch.setattr(
        module.filedialog, "askdirectory", lambda **_kwargs: str(tmp_path / "missing")
    )
    app.export()
    assert "unavailable" in app.status.get()


def test_explicit_retention_confirmation_removes_only_selected_local_copy(
    app, tmp_path, monkeypatch
):
    """Cancellation preserves data; confirmation deletes one exact DB bundle without touching a prior export."""
    app.remove_history()
    assert "Select" in app.status.get()
    app.review_selected()
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    app.history_table.selection_set("1")
    exported = app.state.export(1, tmp_path, project.PRODUCT)
    original = app.state.files(1)
    monkeypatch.setattr(module.messagebox, "askyesno", lambda *_args, **_kwargs: False)
    app.remove_button.invoke()
    assert app.state.files(1) == original
    monkeypatch.setattr(module.messagebox, "askyesno", lambda *_args, **_kwargs: True)
    app.remove_button.invoke()
    assert app.state.history() == [] and app.selected_run == 0
    assert {path.name: path.read_bytes() for path in exported.iterdir()} == original
    app.busy = True
    app.remove_history()
    assert "Wait" in app.status.get()
    app.busy = False


def test_input_selection_cancel_busy_failure_and_literal_row_cap(
    app, tmp_path, monkeypatch
):
    """Operator mistakes do not silently run a prepared fixture, overwrite results or defeat close semantics."""
    name = "policy"
    monkeypatch.setattr(
        module.filedialog,
        "askopenfilename",
        lambda **_kwargs: str(tmp_path / "authorized.json"),
    )
    monkeypatch.setattr(
        module.filedialog,
        "askopenfilenames",
        lambda **_kwargs: ("one.json", "two.json"),
    )
    monkeypatch.setattr(
        module.filedialog, "askdirectory", lambda **_kwargs: str(tmp_path)
    )
    for kind in ("file", "files", "directory"):
        app.authorized.set(True)
        app.choose(name, kind)
        assert app.authorized.get() is False
    value = app.values[name].get()
    monkeypatch.setattr(module.filedialog, "askopenfilename", lambda **_kwargs: "")
    app.choose(name, "file")
    assert app.values[name].get() == value
    app.busy = True
    app.choose(name, "file")
    app.load_prepared()
    app.open_history()
    app.run()
    assert app.state.history() == []
    app.busy = False
    app.load_prepared()
    app.mode.set("unsupported-operation")
    app.authorized.set(True)
    app.run()
    settle(app)
    assert "rejected" in app.status.get().lower() and app.state.history() == []
    app.current = {
        "bounded": [
            {"kind": "alert", "packet": index, "rule": str(index)}
            for index in range(5001)
        ]
    }
    app.view.set("bounded")
    app.render()
    assert len(app.table.get_children()) == 5000
    app.search.set('"5000"')
    assert len(app.table.get_children()) == 1
    app.exit()
    app.run()
    app.poll()
    assert app.root.destroyed and app.state.lock == -1


def test_close_retains_lock_until_actual_core_transaction_finishes(
    app, tmp_path, monkeypatch
):
    """An in-flight real analysis is drained rather than abandoned, force-killed or exposed to a second owner."""
    ready, release = threading.Event(), threading.Event()
    actual = project.analyze

    def pause(*args):
        """Control only scheduling; completion still invokes the actual project core and durable output."""
        ready.set()
        assert release.wait(5)
        return actual(*args)

    monkeypatch.setattr(project, "analyze", pause)
    app.authorized.set(True)
    app.run_button.invoke()
    assert ready.wait(3)
    app.exit()
    app.poll()
    assert not app.root.destroyed and app.busy
    with pytest.raises((Rejected, OSError)):
        Workspace(app.state.path, project.PRODUCT, project.ROOT)
    release.set()
    settle(app)
    assert app.root.destroyed and app.state.lock == -1
    reopened = Workspace(app.state.path, project.PRODUCT, project.ROOT)
    try:
        assert len(reopened.history()) == 1
    finally:
        reopened.close()


def test_main_native_close_and_rejected_acceptance_paths(
    tmp_path, presentation, monkeypatch
):
    """Normal startup never auto-analyzes; test flags cannot enter existing real-profile state or claim partial success."""
    actual = module.Workbench

    def create(root, state):
        """Use actual controls/controller; request the normal close callback at the start of the event loop."""
        window = actual(root, state)
        root.on_loop = window.exit
        return window

    monkeypatch.setattr(module, "Workbench", create)
    profile = tmp_path / "normal"
    assert module.main(["--profile", str(profile)]) == 0
    reopened = Workspace(profile, project.PRODUCT, project.ROOT)
    assert reopened.history() == []
    reopened.close()
    with pytest.raises(SystemExit):
        module.main(["--acceptance-output", str(tmp_path / "output")])
    with pytest.raises(SystemExit):
        module.main(["--acceptance-reopen"])
    assert (
        module.main(
            ["--profile", str(profile), "--acceptance-output", str(tmp_path / "output")]
        )
        == 2
    )
    assert (
        module.main(
            [
                "--profile",
                str(tmp_path / "synthetic"),
                "--acceptance-output",
                str(tmp_path / "new-output"),
            ]
        )
        == 2
    )
    unknown = tmp_path / "unknown"
    unknown.mkdir()
    (unknown / "keep").write_bytes(b"unchanged")
    assert module.main(["--profile", str(unknown)]) == 2
    assert (unknown / "keep").read_bytes() == b"unchanged"
    assert presentation and "No saved evidence was reset" in presentation[-1][1]

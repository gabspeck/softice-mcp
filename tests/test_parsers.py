from __future__ import annotations

from softice_mcp.parsers import (
    detect_popped_in,
    extract_command_output,
    has_more_pager,
    parse_addr_table,
    parse_breakpoint_list,
    parse_disasm,
    parse_eval_result,
    parse_memory_dump,
    parse_mod_table,
    parse_register_dump,
    parse_status_owner,
)


def make_grid(
    command_area: list[str],
    *,
    register_pane: bool = True,
    separator: bool = True,
) -> list[str]:
    """Build a synthetic 25x80 pyte-style grid.

    ``command_area`` lines start at row 17 (stock layout's command bounds).
    Remaining rows are blank unless ``register_pane`` is True, in which case
    we paint register lines at rows 0-2. ``separator`` paints the SoftICE
    pane divider at row 16 so detectors that look for ``---`` succeed.
    """
    rows = [" " * 80 for _ in range(25)]
    if register_pane:
        rows[0] = (
            "EAX=00000001 EBX=00000002 ECX=00000003 EDX=00000004 "
            "ESI=00000005 EDI=00000006"
        ).ljust(80)
        rows[1] = (
            "EIP=00401000 ESP=0063FF00 EBP=0063FF10 CS=001F  "
            "DS=0027 SS=0027 ES=0027 FS=003F"
        ).ljust(80)
        rows[2] = ("   o  d  I  s  z  a  p  c").ljust(80)
    if separator:
        rows[16] = ("-" * 73 + "PROT32-").ljust(80)
    for i, line in enumerate(command_area):
        if 17 + i < 25:
            rows[17 + i] = line.ljust(80)
    return rows


# ---- extractor + detectors -----------------------------------------------


class TestExtractCommandOutput:
    def test_basic_extract(self):
        rows = make_grid(
            [
                ":? 1+1",
                "  00000002  0000000002  \".\"",
                ":",
                "",
                "",
                "",
                "",
                "",
            ]
        )
        out, err, _ = extract_command_output(rows, "? 1+1", (17, 24), cursor_row=19)
        assert err is None
        assert out == ['  00000002  0000000002  "."']

    def test_prompt_not_found(self):
        rows = make_grid(["no prompt here"])
        out, err, _ = extract_command_output(rows, "X", (17, 24), cursor_row=20)
        assert err == "prompt_not_found"
        assert out == []

    def test_trailing_blanks_stripped(self):
        rows = make_grid([":R", "EAX=0 EBX=0", "", "   ", ":", "", "", ""])
        out, err, _ = extract_command_output(rows, "R", (17, 24), cursor_row=21)
        assert err is None
        assert out == ["EAX=0 EBX=0"]

    def test_empty_echo_still_works(self):
        """When paging continues, we feed '' as echo_line; extractor falls back."""
        rows = make_grid(["line1", "line2", "line3", ":", "", "", "", ""])
        out, err, _ = extract_command_output(rows, "", (17, 24), cursor_row=20)
        assert err is None
        assert out == ["line1", "line2", "line3"]

    def test_echo_without_colon_prefix(self):
        """Scrolled Command window sometimes loses the leading `:` on the echo
        row; stripping to bare command text must still identify it as echo."""
        rows = make_grid([" ADDR Explorer", ":", "", "", "", "", "", ""])
        out, err, _ = extract_command_output(rows, "ADDR Explorer", (17, 24), cursor_row=18)
        assert err is None
        assert out == []

    def test_expanded_window_ignores_stale_echoes(self):
        """With the Code/Data panes hidden (WC+WD), the Command window spans
        rows 4..24 and prior-command echoes stay visible in the top portion.
        The extractor must anchor on the bottommost bare `:` prompt rather
        than on a `:COMMAND` echo higher up."""
        rows = [" " * 80 for _ in range(25)]
        rows[4] = ":BC *".ljust(80)
        rows[5] = ":ADDR Explorer".ljust(80)
        rows[6] = ":WC".ljust(80)
        rows[7] = ":WD".ljust(80)
        rows[8] = ":BL".ljust(80)
        rows[9] = "00) BPX 0030:00401000".ljust(80)
        rows[10] = "01) BPX 0030:00402000".ljust(80)
        rows[11] = ":".ljust(80)
        rows[12] = "     Enter a command (H for help)             KERNEL32".ljust(80)
        # cursor parked on the status bar — forces the walk to ignore it.
        out, err, _ = extract_command_output(rows, "BL", (4, 24), cursor_row=12)
        assert err is None
        assert out == ["00) BPX 0030:00401000", "01) BPX 0030:00402000"]

    def test_prefers_most_recent_echo(self):
        """If two `:BL` echoes are visible (a prior BL scrolled but stayed
        on-screen), the extractor must anchor on the more recent one so its
        output is returned, not the older one's."""
        rows = [" " * 80 for _ in range(25)]
        rows[17] = ":BL".ljust(80)
        rows[18] = "XX) OLD DATA".ljust(80)
        rows[19] = ":".ljust(80)
        rows[20] = ":BL".ljust(80)
        rows[21] = "00) BPX 0030:00401000".ljust(80)
        rows[22] = ":".ljust(80)
        out, err, _ = extract_command_output(rows, "BL", (17, 24), cursor_row=22)
        assert err is None
        assert out == ["00) BPX 0030:00401000"]

    def test_pager_marker_as_prompt(self):
        """When SoftICE's pager is active, the bottom row shows `More?` (or
        `press any key`) instead of a bare `:` prompt. The extractor must
        accept that as a terminator so cmd_with_extract's paging loop gets
        the current page's output."""
        rows = make_grid(
            [
                ":BL",
                "00) BPX 0030:00401000",
                "01) BPX 0030:00402000",
                "02) BPX 0030:00403000",
                "03) BPX 0030:00404000",
                "04) BPX 0030:00405000",
                "05) BPX 0030:00406000",
                "More?",
            ]
        )
        out, err, _ = extract_command_output(rows, "BL", (17, 24), cursor_row=24)
        assert err is None
        assert out == [
            "00) BPX 0030:00401000",
            "01) BPX 0030:00402000",
            "02) BPX 0030:00403000",
            "03) BPX 0030:00404000",
            "04) BPX 0030:00405000",
            "05) BPX 0030:00406000",
        ]

    def test_prompt_not_found_when_cursor_mid_output(self):
        """If the drain returned before SoftICE painted a fresh prompt or a
        pager marker, the extractor must fail loudly rather than silently
        anchoring on a `:COMMAND` echo higher up."""
        rows = make_grid(
            [
                ":BL",
                "00) BPX 0030:00401000",
                "01) BPX 0030:00402000",
                "",
                "",
                "",
                "",
                "",
            ]
        )
        out, err, _ = extract_command_output(rows, "BL", (17, 24), cursor_row=20)
        assert err == "prompt_not_found"
        assert out == []


class TestDetectPoppedIn:
    def test_true(self):
        rows = make_grid([":", "", "", "", "", "", "", ""])
        assert detect_popped_in(rows, (17, 24)) is True

    def test_true_even_without_register_labels(self):
        """Register values repaint without their EAX=/EBX= labels, so detection
        must not depend on literal label text in row 0."""
        rows = make_grid([":", "", "", "", "", "", "", ""], register_pane=False)
        # Separator is still present (matching real SoftICE mid-session)
        assert detect_popped_in(rows, (17, 24)) is True

    def test_prompt_is_the_only_signal(self):
        """Even without a separator bar, a ``:`` in the bottom half means popped."""
        rows = make_grid([":", "", "", "", "", "", "", ""], separator=False)
        assert detect_popped_in(rows, (17, 24)) is True

    def test_no_prompt(self):
        rows = make_grid(["no colon here", "", "", "", "", "", "", ""])
        assert detect_popped_in(rows, (17, 24)) is False

    def test_prompt_in_top_half_doesnt_count(self):
        """A ``:`` in row 0-12 could be a register value colon or pane text,
        not SoftICE's Command-window prompt."""
        rows = [" " * 80 for _ in range(25)]
        rows[5] = ":".ljust(80)
        assert detect_popped_in(rows, (17, 24)) is False

    def test_windows_active_means_detached(self):
        """After `G`, pyte still shows the echoed `:G …` in the command window
        and `Windows is active` lands on the host status line. Neither signal
        should be read as popped."""
        rows = [" " * 80 for _ in range(25)]
        rows[17] = ":G KERNEL32!CreateFileA".ljust(80)
        rows[24] = "Windows is active".ljust(80)
        assert detect_popped_in(rows, (17, 24)) is False

    def test_echoed_non_prompt_at_bottom(self):
        """Last non-blank row in the command window is the echoed G command,
        not a fresh ':' — SoftICE resumed and hasn't repainted a new prompt."""
        rows = [" " * 80 for _ in range(25)]
        rows[17] = ":G 400000".ljust(80)
        assert detect_popped_in(rows, (17, 24)) is False

    def test_command_window_status_bar(self):
        """Real SoftICE paints its command-window status bar
        ``Enter a command (H for help) ... <module>`` below the prompt row
        whenever it's popped. The ``:`` prompt is no longer the last
        non-blank row, but the status bar itself is a reliable positive
        signal."""
        rows = [" " * 80 for _ in range(25)]
        rows[21] = ":".ljust(80)
        rows[22] = "     Enter a command (H for help)                      KERNEL32".ljust(80)
        assert detect_popped_in(rows, (17, 24)) is True


class TestHasMorePager:
    def test_more_marker(self):
        rows = make_grid(["foo", "bar", "More?", "", "", "", "", ""])
        assert has_more_pager(rows, (17, 24)) is True

    def test_press_any_key(self):
        rows = make_grid(["foo", "press any key to continue", "", "", "", "", "", ""])
        assert has_more_pager(rows, (17, 24)) is True

    def test_none(self):
        rows = make_grid([":", "", "", "", "", "", "", ""])
        assert has_more_pager(rows, (17, 24)) is False


# ---- register dump -------------------------------------------------------


class TestParseRegisterDump:
    def test_happy(self):
        rows = make_grid([":", "", "", "", "", "", "", ""])
        rows[1] = (
            "EIP=00401000 ESP=0063FF00 EBP=0063FF10 CS=001F "
            "DS=0027 SS=0027 ES=0027 FS=003F"
        ).ljust(80)
        rows[2] = "   OF DF IF SF ZF AF PF CF".ljust(80)
        parsed = parse_register_dump(rows)
        assert parsed["parse_error"] is None
        regs = parsed["parsed"]["registers"]
        assert regs["EAX"] == 1
        assert regs["EBX"] == 2
        assert regs["EIP"] == 0x401000
        assert regs["CS"] == 0x1F
        assert "IF" in parsed["parsed"]["flags_set"]
        assert "ZF" in parsed["parsed"]["flags_set"]

    def test_no_pane(self):
        rows = [" " * 80 for _ in range(3)]
        parsed = parse_register_dump(rows)
        assert parsed["parse_error"] == "no_register_pane"
        assert parsed["parsed"] is None


# ---- eval ----------------------------------------------------------------


class TestParseEvalResult:
    def test_happy(self):
        rows = ['  00000002  0000000002  "."']
        parsed = parse_eval_result(rows)
        assert parsed["parse_error"] is None
        assert parsed["parsed"]["hex"] == 2
        assert parsed["parsed"]["dec"] == 2

    def test_without_ascii(self):
        rows = ["  00000002  0000000002"]
        parsed = parse_eval_result(rows)
        assert parsed["parsed"]["hex"] == 2
        assert parsed["parsed"]["ascii"] == ""

    def test_with_hex_prefix(self):
        rows = ['  0x400000  4194304  "   "']
        parsed = parse_eval_result(rows)
        assert parsed["parsed"]["hex"] == 0x400000
        assert parsed["parsed"]["dec"] == 4194304

    def test_no_match(self):
        rows = ["garbled output"]
        parsed = parse_eval_result(rows)
        assert parsed["parse_error"] == "no_eval_row"
        assert parsed["parsed"] is None


# ---- memory dump ---------------------------------------------------------


class TestParseMemoryDump:
    def test_basic_byte_dump(self):
        rows = [
            "0030:00401000  55 8B EC 83 EC 08 56 57-33 C0 33 DB 33 C9 33 D2  U.....VW3.3.3.3.",
            "0030:00401010  33 F6 33 FF 33 ED 33 E4-90 90 90 90 90 90 90 90  3.3.3.3.........",
        ]
        parsed = parse_memory_dump(rows)
        assert parsed["parse_error"] is None
        assert parsed["parsed"]["address"] == 0x00401000
        assert len(parsed["parsed"]["bytes"]) == 32
        assert parsed["parsed"]["bytes"][0] == 0x55
        assert parsed["parsed"]["bytes"][1] == 0x8B
        assert parsed["parsed"]["lines"][0]["seg_offset"] == "0030:00401000"

    def test_no_rows(self):
        parsed = parse_memory_dump(["not a dump line"])
        assert parsed["parse_error"] == "no_dump_rows"
        assert parsed["parsed"] is None


# ---- disasm --------------------------------------------------------------


class TestParseDisasm:
    def test_basic(self):
        rows = [
            "0030:00401000 55               PUSH   EBP",
            "0030:00401001 8BEC             MOV    EBP,ESP",
            "0030:00401003 83EC08           SUB    ESP,08",
        ]
        parsed = parse_disasm(rows)
        assert parsed["parse_error"] is None
        insns = parsed["parsed"]["instructions"]
        assert len(insns) == 3
        assert insns[0]["address"] == 0x401000
        assert insns[0]["mnemonic"] == "PUSH"
        assert insns[0]["operands"] == "EBP"
        assert insns[0]["annotation"] == ""
        assert insns[1]["mnemonic"] == "MOV"
        assert insns[1]["operands"] == "EBP,ESP"

    def test_trailing_jump_annotation(self):
        """SoftICE paints `(JUMP)` / `(NO JUMP)` beside conditional branches;
        they must land in `annotation`, not leak into `operands`."""
        rows = [
            "0028:C00036A6  JNZ       C00036BD                                 (NO JUMP)",
            "0028:00401200  JZ        00401230                                 (JUMP)",
        ]
        parsed = parse_disasm(rows)
        insns = parsed["parsed"]["instructions"]
        assert insns[0]["operands"] == "C00036BD"
        assert insns[0]["annotation"] == "(NO JUMP)"
        assert insns[1]["operands"] == "00401230"
        assert insns[1]["annotation"] == "(JUMP)"

    def test_memory_ref_annotation(self):
        """At current EIP, SoftICE appends the dereferenced memory value
        (`DS:00401234=DEADBEEF`) after the operands."""
        rows = [
            "0028:C00034C5  MOV       EDI,[C00106A8]  DS:C00106A8=C959F068",
        ]
        parsed = parse_disasm(rows)
        insn = parsed["parsed"]["instructions"][0]
        assert insn["operands"] == "EDI,[C00106A8]"
        assert insn["annotation"] == "DS:C00106A8=C959F068"

    def test_truncated_annotation_preserved(self):
        """Pyte's 80-col buffer can chop the closing `)` off annotations;
        whatever's captured should still land in `annotation`, not operands."""
        rows = [
            "247:0070  JNZ       00A3                                         (JUMP",
        ]
        parsed = parse_disasm(rows)
        insn = parsed["parsed"]["instructions"][0]
        assert insn["operands"] == "00A3"
        assert insn["annotation"] == "(JUMP"

    def test_no_bytes_column(self):
        """SoftICE's 80-col VT100 U output sometimes omits the code-bytes column
        entirely (just `addr  MNEMONIC  OPERANDS`). The parser must still
        recognise these as valid instructions with an empty `bytes` field."""
        rows = [
            "0030:00401000                   PUSH   EBP",
            "0030:00401001                   MOV    EBP,ESP",
        ]
        parsed = parse_disasm(rows)
        assert parsed["parse_error"] is None
        insns = parsed["parsed"]["instructions"]
        assert len(insns) == 2
        assert insns[0]["mnemonic"] == "PUSH"
        assert insns[0]["bytes"] == ""
        assert insns[0]["annotation"] == ""
        assert insns[1]["operands"] == "EBP,ESP"

    def test_no_match(self):
        parsed = parse_disasm(["nothing here"])
        assert parsed["parse_error"] == "no_instructions"


# ---- breakpoint list -----------------------------------------------------


class TestParseBreakpointList:
    def test_plain_bpx(self):
        rows = ["00) BPX  0030:00401000"]
        parsed = parse_breakpoint_list(rows)
        assert parsed["parse_error"] is None
        bp = parsed["parsed"]["breakpoints"][0]
        assert bp["index"] == 0
        assert bp["enabled"] is True
        assert bp["kind"] == "BPX"
        assert "00401000" in bp["target"]

    def test_disabled(self):
        rows = ["01) * BPX  0030:00401000"]
        parsed = parse_breakpoint_list(rows)
        bp = parsed["parsed"]["breakpoints"][0]
        assert bp["enabled"] is False

    def test_with_condition_and_action(self):
        rows = ['02) BPX  401000 IF (EAX==1) DO "R;D ESI"']
        parsed = parse_breakpoint_list(rows)
        bp = parsed["parsed"]["breakpoints"][0]
        assert bp["condition"] == "(EAX==1)"
        assert bp["action"] == "R;D ESI"

    def test_bpmd(self):
        rows = ["03) BPMD 0030:00402000 RW"]
        parsed = parse_breakpoint_list(rows)
        bp = parsed["parsed"]["breakpoints"][0]
        assert bp["kind"] == "BPMD"

    def test_no_rows(self):
        parsed = parse_breakpoint_list(["nothing"])
        assert parsed["parse_error"] == "no_breakpoints"


# ---- addr table ----------------------------------------------------------


class TestParseAddrTable:
    def test_status_footer_extracts_owner(self):
        rows = [
            "------------------------------------VMM(01)+26A0--------------------------------",
            ":",
            "     Enter a command (H for help)                                       Mosview",
        ]
        assert parse_status_owner(rows) == "Mosview"

    def test_without_bold_flags_first_row_becomes_current(self):
        # SoftICE documents that the first listed context is the current one.
        rows = [
            "Handle  Owner",
            "  FFBEAE58  MSGSRV32",
            "  FFBEAE90  EXPLORER",
            "  FFBEAEC8  DIRSRV",
        ]
        parsed = parse_addr_table(rows)
        assert parsed["parse_error"] is None
        assert parsed["parsed"]["current"] == "MSGSRV32"
        assert len(parsed["parsed"]["contexts"]) == 3
        assert parsed["parsed"]["contexts"][0]["active"] is True

    def test_bold_row_marks_active_and_sets_current(self):
        # SoftICE bolds the whole active row — bold list is index-aligned
        # with command_rows, so rows[i] bold <=> ctx for that row is active.
        rows = [
            "Handle  Owner",
            "  FFBEAE58  MSGSRV32",
            "  FFBEAE90  EXPLORER",
            "  FFBEAEC8  DIRSRV",
        ]
        bold = [False, False, True, False]
        parsed = parse_addr_table(rows, bold)
        assert parsed["parsed"]["current"] == "EXPLORER"
        actives = [c["owner"] for c in parsed["parsed"]["contexts"] if c["active"]]
        assert actives == ["EXPLORER"]

    def test_bold_list_shorter_than_rows_is_safe(self):
        # Missing entries past the end of the bold list default to not-bold,
        # without raising — covers a drift between command_rows and render_bold
        # if the driver ever gets them out of sync.
        rows = [
            "Handle  Owner",
            "  FFBEAE58  MSGSRV32",
            "  FFBEAE90  EXPLORER",
        ]
        parsed = parse_addr_table(rows, [False, False])  # EXPLORER uncovered
        assert parsed["parsed"]["current"] == "MSGSRV32"
        assert parsed["parsed"]["contexts"][0]["active"] is True

    def test_ignores_winice_noise_rows(self):
        rows = [
            "WINICE: Load32 KERNEL32",
            "WINICE: LogError ERR_00",
            "Handle  Owner",
            "  FFBEAE58  MSGSRV32",
            "Windows is active, press CTRL Z to pop up WINICE",
            "  FFBEAE90  EXPLORER",
        ]
        parsed = parse_addr_table(rows)
        assert parsed["parse_error"] is None
        assert [ctx["owner"] for ctx in parsed["parsed"]["contexts"]] == [
            "MSGSRV32",
            "EXPLORER",
        ]

    def test_truncated_last_row_uses_status_owner(self):
        rows = [
            "Handle    PGTPTR    Tables  Min Addr  Max Addr  Mutex     Owner",
            "CB1148A0  CB115040  01FC    00400000  7FFFF000  CB1148D4  Starter",
            "CB113214  CB113FE8  01FC    00400000  7FFFF000  CB113248  Systray",
            "CB111654  CB11166C  0002    00400000  7FFFF000  CB112048  MMTASK",
            "CB1100CC  CB11051C  0200    00400000  7FFFF000  CB110100  Mprexe",
            "C10D900C  C10D9024  0002    00400000  7FFFF000  C10D9050",
        ]
        parsed = parse_addr_table(rows, status_owner="Mosview")
        assert parsed["parse_error"] is None
        assert parsed["parsed"]["current"] == "Mosview"
        assert parsed["parsed"]["contexts"][-1]["owner"] == "Mosview"
        actives = [ctx["owner"] for ctx in parsed["parsed"]["contexts"] if ctx["active"]]
        assert actives == ["Mosview"]

    def test_empty(self):
        parsed = parse_addr_table([])
        assert parsed["parse_error"] == "no_contexts"


# ---- mod table -----------------------------------------------------------


class TestParseModTable:
    def test_basic(self):
        rows = [
            "hMod     Base      PEHeader  ModuleName   FileName",
            "FFEE0000 BFF70000  BFF702A0  KERNEL32     C:\\WINDOWS\\SYSTEM\\KERNEL32.DLL",
            "FFEE1234 BFF90000  BFF902A0  USER32       C:\\WINDOWS\\SYSTEM\\USER32.DLL",
        ]
        parsed = parse_mod_table(rows)
        assert parsed["parse_error"] is None
        mods = parsed["parsed"]["modules"]
        assert len(mods) == 2
        assert mods[0]["name"] == "KERNEL32"
        assert mods[0]["base"] == 0xBFF70000
        assert mods[0]["hmod"] == 0xFFEE0000
        assert "KERNEL32.DLL" in mods[0]["path"]

    def test_empty(self):
        parsed = parse_mod_table([])
        assert parsed["parse_error"] == "no_modules"

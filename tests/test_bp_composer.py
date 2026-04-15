from __future__ import annotations

import pytest

from softice_mcp.bp_composer import (
    compose_bp,
    compose_bp_mutate,
    format_address,
)


class TestFormatAddress:
    def test_int_uppercase_hex_no_prefix(self):
        assert format_address(0x401234) == "401234"

    def test_int_zero(self):
        assert format_address(0) == "0"

    def test_string_passthrough(self):
        assert format_address("KERNEL32!CreateFileA") == "KERNEL32!CreateFileA"

    def test_string_trimmed(self):
        assert format_address("  cs:eip  ") == "cs:eip"

    def test_negative_int_rejected(self):
        with pytest.raises(ValueError, match="non-negative"):
            format_address(-1)

    def test_bool_rejected(self):
        with pytest.raises(ValueError):
            format_address(True)  # type: ignore[arg-type]

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError, match="non-empty"):
            format_address("")

    def test_newline_in_string_rejected(self):
        with pytest.raises(ValueError, match="newlines"):
            format_address("foo\nbar")


class TestBpx:
    def test_plain(self):
        assert compose_bp("bpx", 0x401000) == "BPX 401000"

    def test_symbolic(self):
        assert compose_bp("bpx", "USER32!MessageBoxA") == "BPX USER32!MessageBoxA"

    def test_with_condition(self):
        line = compose_bp("bpx", 0x401000, condition="EAX==1")
        assert line == "BPX 401000 IF (EAX==1)"

    def test_condition_already_parenthesized(self):
        line = compose_bp("bpx", 0x401000, condition="(EAX==1 || EBX==2)")
        assert line == "BPX 401000 IF (EAX==1 || EBX==2)"

    def test_with_actions(self):
        line = compose_bp("bpx", 0x401000, actions=["R", "D ESI"])
        assert line == 'BPX 401000 DO "R;D ESI"'

    def test_condition_and_actions(self):
        line = compose_bp(
            "bpx", 0x401000, condition="EAX==1", actions=["R", "DD ESP L10"]
        )
        assert line == 'BPX 401000 IF (EAX==1) DO "R;DD ESP L10"'

    def test_with_context(self):
        line = compose_bp("bpx", 0x401000, context="DIRSRV")
        assert line == "ADDR DIRSRV; BPX 401000"

    def test_context_with_condition_and_actions(self):
        line = compose_bp(
            "bpx",
            0x401000,
            condition="EAX==1",
            actions=["R"],
            context="DIRSRV",
        )
        assert line == 'ADDR DIRSRV; BPX 401000 IF (EAX==1) DO "R"'

    def test_missing_address_rejected(self):
        with pytest.raises(ValueError, match="requires address"):
            compose_bp("bpx")


class TestBpm:
    def test_byte_read(self):
        assert compose_bp("bpm", 0x402000, size="b", verb="r") == "BPMB 402000 R"

    def test_word_write(self):
        assert compose_bp("bpm", 0x402000, size="w", verb="w") == "BPMW 402000 W"

    def test_dword_readwrite(self):
        assert compose_bp("bpm", 0x402000, size="d", verb="rw") == "BPMD 402000 RW"

    def test_exec(self):
        assert compose_bp("bpm", 0x402000, size="b", verb="x") == "BPMB 402000 X"

    def test_uppercase_passthrough(self):
        line = compose_bp("bpm", 0x402000, size="D", verb="RW")
        assert line == "BPMD 402000 RW"

    def test_missing_size(self):
        with pytest.raises(ValueError, match="requires size"):
            compose_bp("bpm", 0x402000, verb="r")

    def test_missing_verb(self):
        with pytest.raises(ValueError, match="requires verb"):
            compose_bp("bpm", 0x402000, size="b")

    def test_bad_size(self):
        with pytest.raises(ValueError, match="requires size"):
            compose_bp("bpm", 0x402000, size="q", verb="r")

    def test_bad_verb(self):
        with pytest.raises(ValueError, match="requires verb"):
            compose_bp("bpm", 0x402000, size="b", verb="q")


class TestBpio:
    def test_basic(self):
        assert compose_bp("bpio", port=0x3F8, verb="r") == "BPIO 3F8 R"

    def test_rw(self):
        assert compose_bp("bpio", port=0x3F8, verb="rw") == "BPIO 3F8 RW"

    def test_out_of_range(self):
        with pytest.raises(ValueError, match=r"\[0, 0xFFFF\]"):
            compose_bp("bpio", port=0x10000, verb="r")

    def test_missing_verb(self):
        with pytest.raises(ValueError, match="requires verb"):
            compose_bp("bpio", port=0x3F8)

    def test_x_verb_rejected(self):
        with pytest.raises(ValueError, match="requires verb"):
            compose_bp("bpio", port=0x3F8, verb="x")


class TestBpint:
    def test_basic(self):
        assert compose_bp("bpint", intno=0x21) == "BPINT 21"

    def test_out_of_range(self):
        with pytest.raises(ValueError, match=r"\[0, 0xFF\]"):
            compose_bp("bpint", intno=0x100)

    def test_missing_intno(self):
        with pytest.raises(ValueError, match="requires intno"):
            compose_bp("bpint")


class TestActionValidation:
    def test_raw_doublequote_rejected(self):
        with pytest.raises(ValueError, match="double-quotes"):
            compose_bp("bpx", 0x401000, actions=['D "ESI"'])

    def test_newline_rejected(self):
        with pytest.raises(ValueError, match="newlines"):
            compose_bp("bpx", 0x401000, actions=["R\nD ESI"])

    def test_empty_action_rejected(self):
        with pytest.raises(ValueError, match="non-empty"):
            compose_bp("bpx", 0x401000, actions=["   "])


class TestContextValidation:
    def test_empty_context_rejected(self):
        with pytest.raises(ValueError, match="non-empty"):
            compose_bp("bpx", 0x401000, context="")

    def test_context_with_semicolon_rejected(self):
        with pytest.raises(ValueError, match="separators"):
            compose_bp("bpx", 0x401000, context="DIR;BAD")


class TestKindValidation:
    def test_unknown_kind(self):
        with pytest.raises(ValueError, match="kind must be one of"):
            compose_bp("bogus", 0x401000)


class TestMutate:
    def test_clear(self):
        assert compose_bp_mutate("clear", 3) == "BC 3"

    def test_enable(self):
        assert compose_bp_mutate("enable", 0) == "BE 0"

    def test_disable(self):
        assert compose_bp_mutate("disable", 5) == "BD 5"

    def test_wildcard(self):
        assert compose_bp_mutate("clear", "*") == "BC *"

    def test_bad_op(self):
        with pytest.raises(ValueError, match="op must be"):
            compose_bp_mutate("bogus", 1)

    def test_bad_index_string(self):
        with pytest.raises(ValueError, match="must be an int"):
            compose_bp_mutate("clear", "abc")

    def test_negative_index(self):
        with pytest.raises(ValueError, match="non-negative"):
            compose_bp_mutate("clear", -1)

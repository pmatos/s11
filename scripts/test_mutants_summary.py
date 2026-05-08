"""Tests for scripts/mutants_summary.py.

Run with: python3 -m unittest scripts/test_mutants_summary.py
"""

import contextlib
import io
import pathlib
import tempfile
import unittest

import mutants_summary as ms


class TestCountLines(unittest.TestCase):
    def test_missing_file_returns_zero(self):
        self.assertEqual(ms.count_lines(pathlib.Path("/no/such/file.txt")), 0)

    def test_counts_lines_in_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "x.txt"
            p.write_text("a\nb\nc\n")
            self.assertEqual(ms.count_lines(p), 3)

    def test_empty_file_returns_zero(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "x.txt"
            p.write_text("")
            self.assertEqual(ms.count_lines(p), 0)

    def test_no_trailing_newline_still_counts(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "x.txt"
            p.write_text("a\nb")
            self.assertEqual(ms.count_lines(p), 2)


class TestReadShard(unittest.TestCase):
    def _make_shard(self, root: pathlib.Path, **buckets: int) -> None:
        root.mkdir(parents=True, exist_ok=True)
        for name, n in buckets.items():
            (root / f"{name}.txt").write_text("\n".join(f"m{i}" for i in range(n)) + ("\n" if n else ""))

    def test_reads_all_five_buckets(self):
        with tempfile.TemporaryDirectory() as d:
            shard = pathlib.Path(d) / "mutants-shard-0"
            self._make_shard(shard, caught=10, missed=2, timeout=1, unviable=3, unrun=0)
            counts = ms.read_shard(shard)
            self.assertEqual(
                counts,
                {"caught": 10, "missed": 2, "timeout": 1, "unviable": 3, "unrun": 0},
            )

    def test_missing_bucket_files_count_as_zero(self):
        with tempfile.TemporaryDirectory() as d:
            shard = pathlib.Path(d) / "empty"
            shard.mkdir()
            counts = ms.read_shard(shard)
            self.assertEqual(
                counts,
                {"caught": 0, "missed": 0, "timeout": 0, "unviable": 0, "unrun": 0},
            )


class TestAggregate(unittest.TestCase):
    def _make_shard(self, root: pathlib.Path, **buckets: int) -> None:
        root.mkdir(parents=True, exist_ok=True)
        for name, n in buckets.items():
            (root / f"{name}.txt").write_text("\n".join(f"m{i}" for i in range(n)) + ("\n" if n else ""))

    def test_aggregates_multiple_shards(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self._make_shard(root / "mutants-shard-0", caught=5, missed=1, timeout=0, unviable=0, unrun=0)
            self._make_shard(root / "mutants-shard-1", caught=3, missed=2, timeout=1, unviable=0, unrun=0)
            result = ms.aggregate(root)
            self.assertEqual([s[0] for s in result["shards"]], ["mutants-shard-0", "mutants-shard-1"])
            self.assertEqual(result["totals"]["caught"], 8)
            self.assertEqual(result["totals"]["missed"], 3)
            self.assertEqual(result["totals"]["timeout"], 1)

    def test_treats_root_with_bucket_files_as_single_shard(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d) / "mutants.out"
            self._make_shard(root, caught=4, missed=2, timeout=0, unviable=0, unrun=0)
            result = ms.aggregate(root)
            self.assertEqual(len(result["shards"]), 1)
            self.assertEqual(result["shards"][0][0], "mutants.out")
            self.assertEqual(result["totals"]["caught"], 4)

    def test_empty_root_yields_zero_totals(self):
        with tempfile.TemporaryDirectory() as d:
            result = ms.aggregate(pathlib.Path(d))
            self.assertEqual(result["shards"], [])
            self.assertEqual(result["totals"], dict.fromkeys(ms.BUCKETS, 0))


class TestFormatSummaryMd(unittest.TestCase):
    def _agg(self, shards, totals):
        return {"shards": shards, "totals": totals}

    def test_header_lists_buckets_in_order(self):
        agg = self._agg(
            [("s0", {"caught": 0, "missed": 0, "timeout": 0, "unviable": 0, "unrun": 0})],
            dict.fromkeys(ms.BUCKETS, 0),
        )
        out = ms.format_summary_md(agg)
        self.assertIn("| shard | caught | missed | timeout | unviable | unrun |", out)

    def test_per_shard_row_has_counts(self):
        agg = self._agg(
            [("mutants-shard-0", {"caught": 5, "missed": 1, "timeout": 0, "unviable": 2, "unrun": 0})],
            {"caught": 5, "missed": 1, "timeout": 0, "unviable": 2, "unrun": 0},
        )
        out = ms.format_summary_md(agg)
        self.assertIn("| mutants-shard-0 | 5 | 1 | 0 | 2 | 0 |", out)

    def test_totals_row_uses_bold(self):
        agg = self._agg(
            [
                ("s0", {"caught": 5, "missed": 1, "timeout": 0, "unviable": 0, "unrun": 0}),
                ("s1", {"caught": 3, "missed": 2, "timeout": 1, "unviable": 0, "unrun": 0}),
            ],
            {"caught": 8, "missed": 3, "timeout": 1, "unviable": 0, "unrun": 0},
        )
        out = ms.format_summary_md(agg)
        self.assertIn("| **total** | **8** | **3** | **1** | **0** | **0** |", out)

    def test_handles_empty_aggregate(self):
        agg = self._agg([], dict.fromkeys(ms.BUCKETS, 0))
        out = ms.format_summary_md(agg)
        self.assertIn("no shards", out.lower())


class TestFormatPrComment(unittest.TestCase):
    def test_includes_totals_line(self):
        out = ms.format_pr_comment(
            totals={"caught": 8, "missed": 3, "timeout": 1, "unviable": 0, "unrun": 0},
            missed_lines=[],
        )
        self.assertIn("caught: 8", out)
        self.assertIn("missed: 3", out)
        self.assertIn("timeout: 1", out)

    def test_lists_first_n_missed_with_default_cap(self):
        missed = [f"src/foo.rs:{i}: replace + with -" for i in range(1, 21)]
        out = ms.format_pr_comment(
            totals={"caught": 0, "missed": 20, "timeout": 0, "unviable": 0, "unrun": 0},
            missed_lines=missed,
        )
        self.assertIn("src/foo.rs:1: replace + with -", out)
        self.assertIn("src/foo.rs:10: replace + with -", out)
        self.assertNotIn("src/foo.rs:11:", out)
        self.assertIn("(showing 10 of 20)", out)

    def test_no_missed_section_when_none(self):
        out = ms.format_pr_comment(
            totals={"caught": 5, "missed": 0, "timeout": 0, "unviable": 0, "unrun": 0},
            missed_lines=[],
        )
        self.assertNotIn("Missed mutants", out)


class TestMainCli(unittest.TestCase):
    def _make_shard(self, root: pathlib.Path, **buckets):
        root.mkdir(parents=True, exist_ok=True)
        for name, content in buckets.items():
            if isinstance(content, int):
                lines = "\n".join(f"m{i}" for i in range(content))
                content = lines + ("\n" if content else "")
            (root / f"{name}.txt").write_text(content)

    def test_main_writes_summary_to_stdout(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self._make_shard(root / "mutants-shard-0", caught=5, missed=1, timeout=0, unviable=0, unrun=0)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ms.main([str(root)])
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("cargo-mutants summary", out)
            self.assertIn("**total**", out)

    def test_main_writes_pr_comment_when_flag_set(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d) / "mutants.out"
            self._make_shard(
                root,
                caught=2,
                missed="src/a.rs:10: replace + with -\nsrc/b.rs:20: delete return\n",
                timeout=0,
                unviable=0,
                unrun=0,
            )
            comment_path = pathlib.Path(d) / "comment.md"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ms.main([str(root), "--pr-comment", str(comment_path)])
            self.assertEqual(rc, 0)
            self.assertTrue(comment_path.exists())
            body = comment_path.read_text()
            self.assertIn("missed: 2", body)
            self.assertIn("src/a.rs:10: replace + with -", body)


if __name__ == "__main__":
    unittest.main()

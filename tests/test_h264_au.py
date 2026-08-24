import unittest

from core.h264_au import AnnexBNALUStream


class AnnexBNALUStreamTests(unittest.TestCase):
    def test_instances_have_independent_buffers(self) -> None:
        first = AnnexBNALUStream()
        second = AnnexBNALUStream()

        first.buffer.extend(b"\x00\x00\x00\x01")

        self.assertEqual(bytes(first.buffer), b"\x00\x00\x00\x01")
        self.assertEqual(bytes(second.buffer), b"")
        self.assertIsNot(first.buffer, second.buffer)


if __name__ == "__main__":
    unittest.main()

"""
Tests for escrow.py - Shamir's Secret Sharing and escrow operations.

Tests the pure GF(256) arithmetic and secret splitting/reconstruction
without requiring database or physical token access.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from escrow import (
    _gf256_mul,
    _gf256_div,
    _evaluate_polynomial,
    _lagrange_interpolate,
    split_secret,
    reconstruct_secret,
)
from crypto import validate_profile_id


class TestGF256Arithmetic:
    """Test Galois Field GF(256) arithmetic operations."""

    def test_mul_identity(self):
        """Multiplying by 1 returns the same element."""
        for x in range(256):
            assert _gf256_mul(x, 1) == x

    def test_mul_zero(self):
        """Multiplying by 0 returns 0."""
        for x in range(256):
            assert _gf256_mul(x, 0) == 0
            assert _gf256_mul(0, x) == 0

    def test_mul_commutative(self):
        """Multiplication is commutative in GF(256)."""
        for a in [1, 2, 17, 128, 255]:
            for b in [1, 3, 42, 200, 254]:
                assert _gf256_mul(a, b) == _gf256_mul(b, a)

    def test_mul_result_in_range(self):
        """All products are within [0, 255]."""
        for a in range(0, 256, 17):
            for b in range(0, 256, 19):
                result = _gf256_mul(a, b)
                assert 0 <= result <= 255

    def test_div_by_one(self):
        """Division by 1 returns the same element."""
        for x in range(256):
            assert _gf256_div(x, 1) == x

    def test_div_zero_numerator(self):
        """0 divided by anything is 0."""
        for x in range(1, 256):
            assert _gf256_div(0, x) == 0

    def test_div_by_zero_raises(self):
        """Division by zero raises ZeroDivisionError."""
        with pytest.raises(ZeroDivisionError):
            _gf256_div(42, 0)

    def test_div_inverse(self):
        """a / a = 1 for all nonzero a."""
        for a in range(1, 256):
            assert _gf256_div(a, a) == 1

    def test_mul_div_roundtrip(self):
        """(a * b) / b = a for nonzero b."""
        for a in [1, 17, 42, 128, 255]:
            for b in [1, 3, 99, 200, 254]:
                product = _gf256_mul(a, b)
                assert _gf256_div(product, b) == a


class TestPolynomialEvaluation:
    """Test polynomial evaluation in GF(256)."""

    def test_constant_polynomial(self):
        """f(x) = c returns c for all x."""
        for c in [0, 1, 42, 255]:
            assert _evaluate_polynomial([c], 0) == c
            assert _evaluate_polynomial([c], 1) == c
            assert _evaluate_polynomial([c], 100) == c

    def test_linear_polynomial_at_zero(self):
        """f(0) returns constant term."""
        assert _evaluate_polynomial([42, 7], 0) == 42

    def test_polynomial_result_in_range(self):
        """All evaluations are within [0, 255]."""
        coeffs = [100, 50, 200]
        for x in range(1, 20):
            result = _evaluate_polynomial(coeffs, x)
            assert 0 <= result <= 255


class TestLagrangeInterpolation:
    """Test Lagrange interpolation in GF(256)."""

    def test_interpolate_two_points(self):
        """Interpolation with 2 points recovers f(0)."""
        # Use a known polynomial: f(x) = 42 + 7x
        secret = 42
        coefficients = [secret, 7]
        p1 = (1, _evaluate_polynomial(coefficients, 1))
        p2 = (2, _evaluate_polynomial(coefficients, 2))
        result = _lagrange_interpolate([p1, p2], 0)
        assert result == secret

    def test_interpolate_three_points(self):
        """Interpolation with 3 points recovers f(0)."""
        secret = 99
        coefficients = [secret, 13, 200]
        points = [(i, _evaluate_polynomial(coefficients, i)) for i in range(1, 4)]
        result = _lagrange_interpolate(points, 0)
        assert result == secret


class TestSplitAndReconstruct:
    """Test Shamir's Secret Sharing split and reconstruct."""

    def test_basic_2_of_3(self):
        """2-of-3 scheme: any 2 shards reconstruct the secret."""
        secret = b"hello world!"
        shards = split_secret(secret, threshold=2, total_shards=3)

        assert len(shards) == 3
        for idx, data in shards:
            assert 1 <= idx <= 3
            assert len(data) == len(secret)

        # Any 2 shards should work
        for combo in [(0, 1), (0, 2), (1, 2)]:
            selected = [shards[i] for i in combo]
            recovered = reconstruct_secret(selected)
            assert recovered == secret

    def test_3_of_5(self):
        """3-of-5 scheme works with exactly 3 shards."""
        secret = os.urandom(32)
        shards = split_secret(secret, threshold=3, total_shards=5)
        assert len(shards) == 5

        # Exactly 3 shards
        recovered = reconstruct_secret(shards[:3])
        assert recovered == secret

        # Different 3 shards
        recovered2 = reconstruct_secret([shards[0], shards[2], shards[4]])
        assert recovered2 == secret

    def test_all_shards_reconstruct(self):
        """Using all shards also works."""
        secret = b"full recovery"
        shards = split_secret(secret, threshold=2, total_shards=4)
        recovered = reconstruct_secret(shards)
        assert recovered == secret

    def test_single_byte_secret(self):
        """Works with a single byte secret."""
        secret = bytes([42])
        shards = split_secret(secret, threshold=2, total_shards=3)
        recovered = reconstruct_secret(shards[:2])
        assert recovered == secret

    def test_256_byte_secret(self):
        """Works with a 256-byte secret (e.g., a 2048-bit key)."""
        secret = os.urandom(256)
        shards = split_secret(secret, threshold=3, total_shards=5)
        recovered = reconstruct_secret(shards[:3])
        assert recovered == secret

    def test_threshold_equals_total(self):
        """Threshold equal to total shards (all required)."""
        secret = b"all required"
        shards = split_secret(secret, threshold=3, total_shards=3)
        recovered = reconstruct_secret(shards)
        assert recovered == secret

    def test_wrong_shard_count_gives_wrong_result(self):
        """Fewer than threshold shards gives wrong result."""
        secret = b"secret data"
        shards = split_secret(secret, threshold=3, total_shards=5)
        # Only 2 shards when 3 are needed - should produce wrong result
        recovered = reconstruct_secret(shards[:2])
        assert recovered != secret

    def test_threshold_exceeds_total_raises(self):
        with pytest.raises(ValueError, match="Threshold cannot exceed"):
            split_secret(b"x", threshold=5, total_shards=3)

    def test_threshold_below_2_raises(self):
        with pytest.raises(ValueError, match="Threshold must be at least 2"):
            split_secret(b"x", threshold=1, total_shards=3)

    def test_too_many_shards_raises(self):
        with pytest.raises(ValueError, match="Maximum 255"):
            split_secret(b"x", threshold=2, total_shards=256)


class TestReconstructEdgeCases:
    """Test reconstruct_secret edge cases."""

    def test_no_shards_raises(self):
        with pytest.raises(ValueError, match="No shards"):
            reconstruct_secret([])

    def test_inconsistent_lengths_raises(self):
        with pytest.raises(ValueError, match="inconsistent lengths"):
            reconstruct_secret([(1, b"abc"), (2, b"ab")])


class TestValidateProfileId:
    """Test profile ID validation."""

    def test_valid_ids(self):
        for pid in ["default", "test-profile", "profile_1", "A123"]:
            validate_profile_id(pid)  # Should not raise

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            validate_profile_id("")

    def test_too_long_raises(self):
        with pytest.raises(ValueError):
            validate_profile_id("a" * 65)

    def test_path_traversal_raises(self):
        with pytest.raises(ValueError):
            validate_profile_id("../etc/passwd")

    def test_starts_with_special_raises(self):
        with pytest.raises(ValueError):
            validate_profile_id("-leading-dash")
        with pytest.raises(ValueError):
            validate_profile_id("_leading-underscore")

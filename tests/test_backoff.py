from fortressflag._backoff import poll_delay_s, retry_delay_s, retry_delay_with_server_hint_s


class _Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[float, float]] = []

    def __call__(self, low: float, high: float) -> float:
        self.calls.append((low, high))
        return (low + high) / 2


def test_retry_doubles_from_2s_and_jitters_20_percent() -> None:
    random = _Capture()
    assert retry_delay_s(1, random) == 2.0
    assert retry_delay_s(2, random) == 4.0
    assert retry_delay_s(3, random) == 8.0
    assert random.calls[0] == (1.6, 2.4)


def test_retry_caps_at_1800s_and_the_exponent_is_capped_before_the_power() -> None:
    random = _Capture()
    assert retry_delay_s(11, random) == 1800.0
    assert retry_delay_s(10_000, random) == 1800.0  # no overflow at absurd counts


def test_zero_failures_waits_zero() -> None:
    assert retry_delay_s(0, _Capture()) == 0.0


def test_poll_delay_jitters_the_success_path_too() -> None:
    random = _Capture()
    assert poll_delay_s(60.0, random) == 60.0
    assert random.calls[0] == (48.0, 72.0)  # ±20% — the de-synchronisation job


def test_server_hint_wins_but_is_capped() -> None:
    random = _Capture()
    assert retry_delay_with_server_hint_s(17, 5, random) == 17.0
    assert retry_delay_with_server_hint_s(31_536_000, 1, random) == 1800.0  # a year → cap
    assert retry_delay_with_server_hint_s(0, 1, random) == 2.0  # no hint → failure schedule

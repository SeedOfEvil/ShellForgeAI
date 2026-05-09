from shellforgeai.core.evidence import TargetType, classify_target


def test_shellforgeai_classifies_as_service() -> None:
    assert classify_target("shellforgeai") == TargetType.service


def test_unknown_single_token_service_classifies_as_service() -> None:
    assert classify_target("frobnicator") == TargetType.service

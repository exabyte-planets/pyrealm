from __future__ import annotations

from pyrealm_forensics.models import Analysis, ArrayNode, RealmHeader, analysis_dict


def test_analysis_dict_recursively_serializes_named_tuples() -> None:
    header = RealmHeader((24, 0), (10, 10), 0, 0, 0, 24, 0, False)
    node = ArrayNode(24, 8, 0, 0, 0, 0, False, False, False, (), "active")
    analysis = Analysis(
        "/sample.realm",
        "digest",
        32,
        "plaintext-realm",
        0.0,
        header,
        (node,),
        (),
    )

    result = analysis_dict(analysis)

    assert isinstance(analysis, tuple)
    assert result["header"] == header._asdict()
    assert result["arrays"] == [node._asdict()]


def test_analysis_dict_handles_missing_header() -> None:
    analysis = Analysis("/sample.bin", "digest", 1, "not-a-plain-realm", 0.0, None, (), ())
    assert analysis_dict(analysis)["header"] is None

rule BDFR_Synthetic_SelfTest
{
    meta:
        author = "BDFR Sentinel"
        purpose = "synthetic self-test marker only"

    strings:
        $marker = "BDFR_YARA_X_MARKER"

    condition:
        $marker
}

package io.myotis.txhistory

/**
 * Host-agnostic display strings for a [TxSummary], shared by the desktop and Android
 * event mappers so the Query tab renders identically on both. (The shared Compose UI
 * itself can't hold these — commonMain must stay free of this JVM module's types, so
 * hosts map [TxHistoryEvent] into the UI's own models and only borrow the formatting.)
 */

/** The UI's short kind tag: "eth" | "erc20" | "call" | "create". */
fun TxSummary.uiKind(): String = when (kind) {
    TxKind.ETH_TRANSFER -> "eth"
    TxKind.ERC20_TRANSFER -> "erc20"
    TxKind.CONTRACT_CALL -> "call"
    TxKind.CONTRACT_CREATION -> "create"
}

/**
 * Succinct one-liner: "1.25 ETH → 0xab12cd…9e4f" / "1250.50 USDC → 0x3086…76e" /
 * "call · 132 bytes calldata · 0x38ed1739" / "contract creation · 4 bytes".
 */
fun TxSummary.headline(): String = when (kind) {
    TxKind.ETH_TRANSFER -> "$ethDisplay ETH → ${shortAddress(to)}"
    TxKind.ERC20_TRANSFER ->
        "${tokenAmount ?: "?"} ${tokenSymbol ?: "?"} → ${shortAddress(tokenRecipient)}"
    TxKind.CONTRACT_CALL -> buildString {
        append("call · ").append(calldataBytes).append(" bytes calldata")
        selector?.let { append(" · ").append(it) }
        if (ethWei != "0") append(" · ").append(ethDisplay).append(" ETH")
    }
    TxKind.CONTRACT_CREATION -> "contract creation · $calldataBytes bytes"
}

/** "0x30868655…276e"-style truncation; "?" for a missing address. */
fun shortAddress(a: String?): String =
    if (a == null || a.length < 12) a ?: "?" else "${a.take(8)}…${a.takeLast(4)}"

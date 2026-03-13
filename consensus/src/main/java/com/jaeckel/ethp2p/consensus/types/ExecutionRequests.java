package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: ExecutionRequests (Electra)
 * deposits(List[DepositRequest, 8192]) + withdrawals(List[WithdrawalRequest, 16])
 * + consolidations(List[ConsolidationRequest, 2])
 * SSZ fixed part: 3 offsets = 12 bytes
 */
public final class ExecutionRequests {

    private static final int MAX_DEPOSIT_REQUESTS = 8192;
    private static final int MAX_WITHDRAWAL_REQUESTS = 16;
    private static final int MAX_CONSOLIDATION_REQUESTS = 2;

    private ExecutionRequests() {}

    /**
     * Compute hash_tree_root from body bytes between [start, end).
     */
    public static byte[] hashTreeRoot(byte[] body, int start, int end) {
        byte[] er = Arrays.copyOfRange(body, start, end);
        if (er.length < 12) {
            return SszUtil.hashTreeRootContainer(
                    SszUtil.emptyListRoot(MAX_DEPOSIT_REQUESTS),
                    SszUtil.emptyListRoot(MAX_WITHDRAWAL_REQUESTS),
                    SszUtil.emptyListRoot(MAX_CONSOLIDATION_REQUESTS)
            );
        }
        int depOff = SszUtil.readUint32(er, 0);
        int wdOff = SszUtil.readUint32(er, 4);
        int conOff = SszUtil.readUint32(er, 8);

        byte[] depRoot = SszUtil.hashFixedElementList(er, depOff, wdOff,
                DepositRequest.SSZ_SIZE, MAX_DEPOSIT_REQUESTS, DepositRequest::hashTreeRootAt);
        byte[] wdRoot = SszUtil.hashFixedElementList(er, wdOff, conOff,
                WithdrawalRequest.SSZ_SIZE, MAX_WITHDRAWAL_REQUESTS, WithdrawalRequest::hashTreeRootAt);
        byte[] conRoot = SszUtil.hashFixedElementList(er, conOff, er.length,
                ConsolidationRequest.SSZ_SIZE, MAX_CONSOLIDATION_REQUESTS, ConsolidationRequest::hashTreeRootAt);

        return SszUtil.hashTreeRootContainer(depRoot, wdRoot, conRoot);
    }
}

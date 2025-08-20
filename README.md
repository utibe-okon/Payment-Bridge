# Payment Bridge Smart Contract

A robust Clarity smart contract implementation for off-chain payment bridges with on-chain settlement on the Stacks blockchain.

## Overview

The Payment Bridge Contract enables two parties to establish secure off-chain payment channels with cryptographic guarantees and on-chain dispute resolution. This implementation allows for high-frequency, low-cost transactions between participants while maintaining the security properties of blockchain settlement.

## Key Features

- **Off-chain Payment Processing**: Execute multiple transactions off-chain with minimal gas costs
- **Cryptographic Security**: ECDSA signature verification for all state transitions
- **Dispute Resolution**: Challenge and counter-challenge mechanism with configurable timeouts
- **Cooperative Closure**: Gas-efficient mutual agreement settlements
- **Emergency Controls**: Admin functions for contract management
- **Fee Management**: Configurable fee structure with basis point precision

## Core Concepts

### Bridge States
- **BRIDGE_ACTIVE** (0): Bridge is operational for off-chain transactions
- **BRIDGE_CHALLENGED** (1): A dispute has been initiated, awaiting resolution
- **BRIDGE_INACTIVE** (2): Bridge is closed but not yet finalized
- **BRIDGE_COMPLETED** (3): Bridge is permanently closed and funds distributed

### Participants
- **Member X**: First participant (bridge creator)
- **Member Y**: Second participant
- Both members must register public keys for signature verification

## Main Functions

### Bridge Management
```clarity
;; Establish a new payment bridge
(establish-bridge member-y deposit-x deposit-y challenge-duration)

;; Add additional funds to existing bridge
(add-funds-to-bridge bridge-id amount)

;; Register public key for signature verification
(store-pubkey pubkey)
```

### State Management
```clarity
;; Update bridge state with signed transaction
(modify-state bridge-id new-funds-x new-funds-y sequence-num confirmation-x confirmation-y)

;; Cooperative closure with mutual agreement
(close-bridge-cooperatively bridge-id final-funds-x final-funds-y confirmation-x confirmation-y)
```

### Dispute Resolution
```clarity
;; Initiate dispute for uncooperative closure
(challenge-bridge bridge-id claimed-funds-x claimed-funds-y sequence-num)

;; Counter a dispute with newer state
(counter-challenge bridge-id new-funds-x new-funds-y sequence-num confirmation-x confirmation-y)

;; Finalize disputed bridge after timeout
(complete-bridge bridge-id)
```

### Read-Only Functions
```clarity
;; Get comprehensive bridge information
(get-bridge-details bridge-id)

;; Check bridge operational status
(is-bridge-active bridge-id)

;; Get member's associated bridges
(get-member-bridges member)

;; Calculate dispute deadline
(get-challenge-deadline bridge-id)
```

## Workflow

### 1. Bridge Establishment
1. Member X calls `store-pubkey` to register their public key
2. Member Y calls `store-pubkey` to register their public key
3. Member X calls `establish-bridge` with initial deposits and challenge duration
4. Both members can add additional funds using `add-funds-to-bridge`

### 2. Off-Chain Operations
1. Members conduct transactions off-chain
2. Each state change is signed by both parties
3. Latest signed state can be submitted on-chain via `modify-state`

### 3. Bridge Closure

#### Cooperative Closure (Recommended)
1. Members agree on final state off-chain
2. Either member calls `close-bridge-cooperatively` with signatures
3. Funds are immediately distributed with fee deduction

#### Non-Cooperative Closure
1. Any member calls `challenge-bridge` with claimed final state
2. Other member has until deadline to `counter-challenge` with newer state
3. After timeout, anyone can call `complete-bridge` to finalize

## Security Features

- **Signature Verification**: All state transitions require valid ECDSA signatures from both members
- **Sequence Number Protection**: Prevents replay attacks and ensures state progression
- **Challenge Period**: Configurable timeout for dispute resolution (default: 144 blocks ≈ 24 hours)
- **Balance Validation**: Ensures total funds remain constant across state transitions
- **Access Control**: Member-only operations and admin functions

## Fee Structure

- Default fee rate: 1% (100 basis points)
- Fees are split equally between members
- Fees are deducted during final settlement
- Admin can update fee rate (maximum 10%)

## Error Codes

| Code | Error | Description |
|------|-------|-------------|
| 100 | ERR_NOT_AUTHORIZED | Caller lacks required permissions |
| 101 | ERR_BRIDGE_NOT_EXISTS | Bridge ID not found |
| 102 | ERR_BRIDGE_EXISTS | Bridge already exists |
| 103 | ERR_BALANCE_TOO_LOW | Insufficient STX balance |
| 104 | ERR_BAD_SIGNATURE | Invalid cryptographic signature |
| 105 | ERR_BRIDGE_INACTIVE | Bridge is not in active state |
| 106 | ERR_BAD_SEQUENCE | Invalid sequence number |
| 107 | ERR_TIMEOUT_ACTIVE | Challenge timeout still active |
| 108 | ERR_BAD_MEMBER | Invalid member address |
| 109 | ERR_NOT_IN_DISPUTE | Bridge not in challenged state |
| 110 | ERR_BAD_VALUE | Invalid amount or calculation |
| 111 | ERR_BRIDGE_COMPLETED | Bridge already finalized |
| 112 | ERR_BAD_DURATION | Invalid timeout duration |
| 113 | ERR_BAD_PUBKEY | Invalid public key format |

## Deployment Requirements

- Stacks blockchain
- Clarity smart contract runtime
- ECDSA signature verification support

## Usage Examples

```clarity
;; Member X establishes bridge with Member Y
(contract-call? .payment-bridge establish-bridge 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7 1000000 500000 u200)

;; Update bridge state with new balances
(contract-call? .payment-bridge modify-state u1 800000 700000 u5 signature-x signature-y)

;; Cooperatively close bridge
(contract-call? .payment-bridge close-bridge-cooperatively u1 600000 900000 final-sig-x final-sig-y)
```

## Best Practices

1. **Always register public keys** before bridge operations
2. **Keep sequence numbers strictly increasing** to prevent replay attacks
3. **Store off-chain signatures securely** for dispute resolution
4. **Use cooperative closure** when possible to minimize fees
5. **Monitor challenge deadlines** during dispute periods
6. **Verify total funds consistency** in all state updates


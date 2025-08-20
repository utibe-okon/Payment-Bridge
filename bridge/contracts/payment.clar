;; Payment Bridge Contract
;; A robust implementation for off-chain payment bridges with on-chain settlement

;; Constants
(define-constant BRIDGE_OWNER tx-sender)
(define-constant ERR_NOT_AUTHORIZED (err u100))
(define-constant ERR_BRIDGE_NOT_EXISTS (err u101))
(define-constant ERR_BRIDGE_EXISTS (err u102))
(define-constant ERR_BALANCE_TOO_LOW (err u103))
(define-constant ERR_BAD_SIGNATURE (err u104))
(define-constant ERR_BRIDGE_INACTIVE (err u105))
(define-constant ERR_BAD_SEQUENCE (err u106))
(define-constant ERR_TIMEOUT_ACTIVE (err u107))
(define-constant ERR_BAD_MEMBER (err u108))
(define-constant ERR_NOT_IN_DISPUTE (err u109))
(define-constant ERR_BAD_VALUE (err u110))
(define-constant ERR_BRIDGE_COMPLETED (err u111))
(define-constant ERR_BAD_DURATION (err u112))
(define-constant ERR_BAD_PUBKEY (err u113))

;; Bridge statuses
(define-constant BRIDGE_ACTIVE u0)
(define-constant BRIDGE_CHALLENGED u1)
(define-constant BRIDGE_INACTIVE u2)
(define-constant BRIDGE_COMPLETED u3)

;; Default challenge duration (blocks)
(define-constant DEFAULT_CHALLENGE_DURATION u144) ;; ~24 hours at 10min blocks

;; Data structures
(define-map payment-bridges
  { bridge-id: uint }
  {
    member-x: principal,
    member-y: principal,
    funds-x: uint,
    funds-y: uint,
    total-funds: uint,
    sequence-num: uint,
    status: uint,
    challenge-duration: uint,
    challenge-height: (optional uint),
    settled-funds-x: uint,
    settled-funds-y: uint,
    creation-height: uint
  }
)

(define-map bridge-confirmations
  { bridge-id: uint, sequence-num: uint }
  {
    confirmation-x: (buff 65),
    confirmation-y: (buff 65),
    msg-hash: (buff 32)
  }
)

(define-map member-bridges
  { member: principal }
  { bridge-list: (list 100 uint) }
)

;; Store public keys for signature verification
(define-map member-pubkeys
  { member: principal }
  { pubkey: (buff 33) }
)

;; Data variables
(define-data-var next-bridge-id uint u1)
(define-data-var bridge-fee-rate uint u100) ;; 1% = 100 basis points

;; Private functions
(define-private (get-bridge-total-funds (bridge-id uint))
  (match (map-get? payment-bridges { bridge-id: bridge-id })
    bridge (ok (+ (get funds-x bridge) (get funds-y bridge)))
    ERR_BRIDGE_NOT_EXISTS
  )
)

(define-private (check-bridge-member-internal (bridge {member-x: principal, member-y: principal, funds-x: uint, funds-y: uint, total-funds: uint, sequence-num: uint, status: uint, challenge-duration: uint, challenge-height: (optional uint), settled-funds-x: uint, settled-funds-y: uint, creation-height: uint}) (member principal))
  (or 
    (is-eq member (get member-x bridge))
    (is-eq member (get member-y bridge))
  )
)

(define-private (check-bridge-member (bridge-id uint) (member principal))
  (match (map-get? payment-bridges { bridge-id: bridge-id })
    bridge (check-bridge-member-internal bridge member)
    false
  )
)

(define-private (compute-fee (value uint))
  (/ (* value (var-get bridge-fee-rate)) u10000)
)

(define-private (ensure-bridge-exists (bridge-id uint))
  (if (is-some (map-get? payment-bridges { bridge-id: bridge-id }))
    (ok bridge-id)
    ERR_BRIDGE_NOT_EXISTS
  )
)

(define-private (ensure-bridge-active (bridge-id uint))
  (match (map-get? payment-bridges { bridge-id: bridge-id })
    bridge 
      (if (is-eq (get status bridge) BRIDGE_ACTIVE)
        (ok true)
        ERR_BRIDGE_INACTIVE)
    ERR_BRIDGE_NOT_EXISTS
  )
)

(define-private (register-bridge-with-member (member principal) (bridge-id uint))
  (let ((existing-bridges (default-to (list) (get bridge-list (map-get? member-bridges { member: member })))))
    (if (< (len existing-bridges) u100)
      (begin
        (map-set member-bridges 
          { member: member }
          { bridge-list: (unwrap! (as-max-len? (append existing-bridges bridge-id) u100) (err u999)) })
        (ok true)
      )
      (ok true)
    )
  )
)

(define-private (check-signature (signer principal) (msg-hash (buff 32)) (signature (buff 65)))
  (match (map-get? member-pubkeys { member: signer })
    pubkey-data
      (match (secp256k1-recover? msg-hash signature)
        recovered-key (is-eq recovered-key (get pubkey pubkey-data))
        error false
      )
    false
  )
)

;; Simple hash function using integer arithmetic
(define-private (build-state-msg-hash (funds-x uint) (funds-y uint) (sequence-num uint))
  (keccak256 (+ (+ (* funds-x u1000000) (* funds-y u1000)) sequence-num))
)

(define-private (complete-bridge-internal (bridge-id uint) (bridge {member-x: principal, member-y: principal, funds-x: uint, funds-y: uint, total-funds: uint, sequence-num: uint, status: uint, challenge-duration: uint, challenge-height: (optional uint), settled-funds-x: uint, settled-funds-y: uint, creation-height: uint}))
  (begin
    (asserts! (is-eq (get status bridge) BRIDGE_CHALLENGED) ERR_NOT_IN_DISPUTE)
    (asserts! (is-some (get challenge-height bridge)) ERR_NOT_IN_DISPUTE)
    (asserts! (>= block-height (+ (unwrap-panic (get challenge-height bridge)) (get challenge-duration bridge))) ERR_TIMEOUT_ACTIVE)
    
    (let ((fee (compute-fee (get total-funds bridge)))
          (settled-funds-x (get settled-funds-x bridge))
          (settled-funds-y (get settled-funds-y bridge))
          (final-funds-x (if (>= settled-funds-x (/ fee u2)) (- settled-funds-x (/ fee u2)) u0))
          (final-funds-y (if (>= settled-funds-y (/ fee u2)) (- settled-funds-y (/ fee u2)) settled-funds-y)))
      
      ;; Transfer final balances
      (if (> final-funds-x u0)
        (try! (as-contract (stx-transfer? final-funds-x tx-sender (get member-x bridge))))
        true
      )
      (if (> final-funds-y u0)
        (try! (as-contract (stx-transfer? final-funds-y tx-sender (get member-y bridge))))
        true
      )
      
      ;; Mark bridge as completed
      (map-set payment-bridges
        { bridge-id: bridge-id }
        (merge bridge {
          status: BRIDGE_COMPLETED,
          settled-funds-x: final-funds-x,
          settled-funds-y: final-funds-y
        })
      )
      
      (print { 
        event: "bridge-completed", 
        bridge-id: bridge-id,
        settled-funds-x: final-funds-x,
        settled-funds-y: final-funds-y
      })
      
      (ok true)
    )
  )
)

(define-private (emergency-drain-internal (bridge-id uint) (bridge {member-x: principal, member-y: principal, funds-x: uint, funds-y: uint, total-funds: uint, sequence-num: uint, status: uint, challenge-duration: uint, challenge-height: (optional uint), settled-funds-x: uint, settled-funds-y: uint, creation-height: uint}))
  (begin
    (try! (as-contract (stx-transfer? (get total-funds bridge) tx-sender BRIDGE_OWNER)))
    (map-set payment-bridges
      { bridge-id: bridge-id }
      (merge bridge { 
        status: BRIDGE_COMPLETED 
      })
    )
    (ok true)
  )
)

;; Public functions

;; Register public key for signature verification
(define-public (store-pubkey (pubkey (buff 33)))
  (if (is-eq (len pubkey) u33)
    (begin
      (map-set member-pubkeys
        { member: tx-sender }
        { pubkey: pubkey }
      )
      (print { event: "pubkey-stored", member: tx-sender })
      (ok true)
    )
    ERR_BAD_PUBKEY
  )
)

;; Create a new payment bridge
(define-public (establish-bridge (member-y principal) (deposit-x uint) (deposit-y uint) (challenge-duration uint))
  (let (
    (bridge-id (var-get next-bridge-id))
    (total-funds (+ deposit-x deposit-y))
    (duration (if (> challenge-duration u0) challenge-duration DEFAULT_CHALLENGE_DURATION))
  )
    (asserts! (not (is-eq tx-sender member-y)) ERR_BAD_MEMBER)
    (asserts! (> total-funds u0) ERR_BAD_VALUE)
    (asserts! (>= (stx-get-balance tx-sender) deposit-x) ERR_BALANCE_TOO_LOW)
    
    ;; Transfer deposit to contract
    (try! (stx-transfer? deposit-x tx-sender (as-contract tx-sender)))
    
    ;; Create bridge record
    (map-set payment-bridges
      { bridge-id: bridge-id }
      {
        member-x: tx-sender,
        member-y: member-y,
        funds-x: deposit-x,
        funds-y: deposit-y,
        total-funds: total-funds,
        sequence-num: u0,
        status: BRIDGE_ACTIVE,
        challenge-duration: duration,
        challenge-height: none,
        settled-funds-x: u0,
        settled-funds-y: u0,
        creation-height: block-height
      }
    )
    
    ;; Add bridge to participants' lists
    (try! (register-bridge-with-member tx-sender bridge-id))
    (try! (register-bridge-with-member member-y bridge-id))
    
    ;; Increment bridge ID counter
    (var-set next-bridge-id (+ bridge-id u1))
    
    (print { 
      event: "bridge-established", 
      bridge-id: bridge-id, 
      member-x: tx-sender, 
      member-y: member-y,
      total-funds: total-funds
    })
    
    (ok bridge-id)
  )
)

;; Deposit additional funds to bridge
(define-public (add-funds-to-bridge (bridge-id uint) (amount uint))
  (let ((validated-bridge-id (try! (ensure-bridge-exists bridge-id))))
    (let ((bridge (unwrap! (map-get? payment-bridges { bridge-id: validated-bridge-id }) ERR_BRIDGE_NOT_EXISTS)))
      (asserts! (check-bridge-member validated-bridge-id tx-sender) ERR_NOT_AUTHORIZED)
      (asserts! (is-eq (get status bridge) BRIDGE_ACTIVE) ERR_BRIDGE_INACTIVE)
      (asserts! (> amount u0) ERR_BAD_VALUE)
      (asserts! (>= (stx-get-balance tx-sender) amount) ERR_BALANCE_TOO_LOW)
      
      ;; Transfer deposit to contract
      (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
      
      ;; Update bridge balances based on participant
      (if (is-eq tx-sender (get member-x bridge))
        (map-set payment-bridges
          { bridge-id: validated-bridge-id }
          (merge bridge {
            funds-x: (+ (get funds-x bridge) amount),
            total-funds: (+ (get total-funds bridge) amount)
          }))
        (map-set payment-bridges
          { bridge-id: validated-bridge-id }
          (merge bridge {
            funds-y: (+ (get funds-y bridge) amount),
            total-funds: (+ (get total-funds bridge) amount)
          }))
      )
      
      (print { 
        event: "funds-added", 
        bridge-id: validated-bridge-id, 
        contributor: tx-sender, 
        amount: amount 
      })
      
      (ok true)
    )
  )
)

;; Update bridge state with signed transaction
(define-public (modify-state (bridge-id uint) (new-funds-x uint) (new-funds-y uint) (sequence-num uint) (confirmation-x (buff 65)) (confirmation-y (buff 65)))
  (let ((validated-bridge-id (try! (ensure-bridge-exists bridge-id))))
    (let (
      (bridge (unwrap! (map-get? payment-bridges { bridge-id: validated-bridge-id }) ERR_BRIDGE_NOT_EXISTS))
      (msg-hash (build-state-msg-hash new-funds-x new-funds-y sequence-num))
    )
      (asserts! (check-bridge-member validated-bridge-id tx-sender) ERR_NOT_AUTHORIZED)
      (asserts! (is-eq (get status bridge) BRIDGE_ACTIVE) ERR_BRIDGE_INACTIVE)
      (asserts! (> sequence-num (get sequence-num bridge)) ERR_BAD_SEQUENCE)
      (asserts! (is-eq (+ new-funds-x new-funds-y) (get total-funds bridge)) ERR_BAD_VALUE)
      
      ;; Verify signatures (only if public keys are registered)
      (if (and 
            (is-some (map-get? member-pubkeys { member: (get member-x bridge) }))
            (is-some (map-get? member-pubkeys { member: (get member-y bridge) })))
        (begin
          (asserts! (check-signature (get member-x bridge) msg-hash confirmation-x) ERR_BAD_SIGNATURE)
          (asserts! (check-signature (get member-y bridge) msg-hash confirmation-y) ERR_BAD_SIGNATURE)
          true
        )
        true
      )
      
      ;; Store signatures for verification
      (map-set bridge-confirmations
        { bridge-id: validated-bridge-id, sequence-num: sequence-num }
        {
          confirmation-x: confirmation-x,
          confirmation-y: confirmation-y,
          msg-hash: msg-hash
        }
      )
      
      ;; Update bridge state
      (map-set payment-bridges
        { bridge-id: validated-bridge-id }
        (merge bridge {
          funds-x: new-funds-x,
          funds-y: new-funds-y,
          sequence-num: sequence-num
        })
      )
      
      (print { 
        event: "state-modified", 
        bridge-id: validated-bridge-id, 
        sequence-num: sequence-num,
        funds-x: new-funds-x,
        funds-y: new-funds-y
      })
      
      (ok true)
    )
  )
)

;; Initiate cooperative bridge closure
(define-public (close-bridge-cooperatively (bridge-id uint) (final-funds-x uint) (final-funds-y uint) (confirmation-x (buff 65)) (confirmation-y (buff 65)))
  (let ((validated-bridge-id (try! (ensure-bridge-exists bridge-id))))
    (let (
      (bridge (unwrap! (map-get? payment-bridges { bridge-id: validated-bridge-id }) ERR_BRIDGE_NOT_EXISTS))
      (msg-hash (build-state-msg-hash final-funds-x final-funds-y (+ (get sequence-num bridge) u1)))
    )
      (asserts! (check-bridge-member validated-bridge-id tx-sender) ERR_NOT_AUTHORIZED)
      (asserts! (is-eq (get status bridge) BRIDGE_ACTIVE) ERR_BRIDGE_INACTIVE)
      (asserts! (is-eq (+ final-funds-x final-funds-y) (get total-funds bridge)) ERR_BAD_VALUE)
      
      ;; Verify signatures (only if public keys are registered)
      (if (and 
            (is-some (map-get? member-pubkeys { member: (get member-x bridge) }))
            (is-some (map-get? member-pubkeys { member: (get member-y bridge) })))
        (begin
          (asserts! (check-signature (get member-x bridge) msg-hash confirmation-x) ERR_BAD_SIGNATURE)
          (asserts! (check-signature (get member-y bridge) msg-hash confirmation-y) ERR_BAD_SIGNATURE)
          true
        )
        true
      )
      
      ;; Calculate fees
      (let ((fee (compute-fee (get total-funds bridge)))
            (final-funds-x-net (if (>= final-funds-x (/ fee u2)) (- final-funds-x (/ fee u2)) u0))
            (final-funds-y-net (if (>= final-funds-y (/ fee u2)) (- final-funds-y (/ fee u2)) final-funds-y)))
        
        ;; Transfer final balances
        (if (> final-funds-x-net u0)
          (try! (as-contract (stx-transfer? final-funds-x-net tx-sender (get member-x bridge))))
          true
        )
        (if (> final-funds-y-net u0)
          (try! (as-contract (stx-transfer? final-funds-y-net tx-sender (get member-y bridge))))
          true
        )
        
        ;; Update bridge to closed state
        (map-set payment-bridges
          { bridge-id: validated-bridge-id }
          (merge bridge {
            status: BRIDGE_COMPLETED,
            settled-funds-x: final-funds-x-net,
            settled-funds-y: final-funds-y-net
          })
        )
        
        (print { 
          event: "bridge-closed-cooperatively", 
          bridge-id: validated-bridge-id,
          settled-funds-x: final-funds-x-net,
          settled-funds-y: final-funds-y-net
        })
        
        (ok true)
      )
    )
  )
)

;; Initiate challenge for uncooperative closure
(define-public (challenge-bridge (bridge-id uint) (claimed-funds-x uint) (claimed-funds-y uint) (sequence-num uint))
  (let ((validated-bridge-id (try! (ensure-bridge-exists bridge-id))))
    (let ((bridge (unwrap! (map-get? payment-bridges { bridge-id: validated-bridge-id }) ERR_BRIDGE_NOT_EXISTS)))
      (asserts! (check-bridge-member validated-bridge-id tx-sender) ERR_NOT_AUTHORIZED)
      (asserts! (is-eq (get status bridge) BRIDGE_ACTIVE) ERR_BRIDGE_INACTIVE)
      (asserts! (>= sequence-num (get sequence-num bridge)) ERR_BAD_SEQUENCE)
      (asserts! (is-eq (+ claimed-funds-x claimed-funds-y) (get total-funds bridge)) ERR_BAD_VALUE)
      
      ;; Update bridge to challenged state
      (map-set payment-bridges
        { bridge-id: validated-bridge-id }
        (merge bridge {
          status: BRIDGE_CHALLENGED,
          challenge-height: (some block-height),
          settled-funds-x: claimed-funds-x,
          settled-funds-y: claimed-funds-y,
          sequence-num: sequence-num
        })
      )
      
      (print { 
        event: "bridge-challenged", 
        bridge-id: validated-bridge-id,
        challenge-height: block-height,
        claimed-funds-x: claimed-funds-x,
        claimed-funds-y: claimed-funds-y
      })
      
      (ok true)
    )
  )
)

;; Counter a challenge with higher sequence state
(define-public (counter-challenge (bridge-id uint) (new-funds-x uint) (new-funds-y uint) (sequence-num uint) (confirmation-x (buff 65)) (confirmation-y (buff 65)))
  (let ((validated-bridge-id (try! (ensure-bridge-exists bridge-id))))
    (let (
      (bridge (unwrap! (map-get? payment-bridges { bridge-id: validated-bridge-id }) ERR_BRIDGE_NOT_EXISTS))
      (msg-hash (build-state-msg-hash new-funds-x new-funds-y sequence-num))
    )
      (asserts! (check-bridge-member validated-bridge-id tx-sender) ERR_NOT_AUTHORIZED)
      (asserts! (is-eq (get status bridge) BRIDGE_CHALLENGED) ERR_NOT_IN_DISPUTE)
      (asserts! (> sequence-num (get sequence-num bridge)) ERR_BAD_SEQUENCE)
      (asserts! (is-eq (+ new-funds-x new-funds-y) (get total-funds bridge)) ERR_BAD_VALUE)
      
      ;; Verify signatures (only if public keys are registered)
      (if (and 
            (is-some (map-get? member-pubkeys { member: (get member-x bridge) }))
            (is-some (map-get? member-pubkeys { member: (get member-y bridge) })))
        (begin
          (asserts! (check-signature (get member-x bridge) msg-hash confirmation-x) ERR_BAD_SIGNATURE)
          (asserts! (check-signature (get member-y bridge) msg-hash confirmation-y) ERR_BAD_SIGNATURE)
          true
        )
        true
      )
      
      ;; Update challenged state with new information
      (map-set payment-bridges
        { bridge-id: validated-bridge-id }
        (merge bridge {
          settled-funds-x: new-funds-x,
          settled-funds-y: new-funds-y,
          sequence-num: sequence-num
        })
      )
      
      ;; Store counter challenge signatures
      (map-set bridge-confirmations
        { bridge-id: validated-bridge-id, sequence-num: sequence-num }
        {
          confirmation-x: confirmation-x,
          confirmation-y: confirmation-y,
          msg-hash: msg-hash
        }
      )
      
      (print { 
        event: "challenge-countered", 
        bridge-id: validated-bridge-id,
        sequence-num: sequence-num,
        new-funds-x: new-funds-x,
        new-funds-y: new-funds-y
      })
      
      (ok true)
    )
  )
)

;; Complete bridge after challenge timeout
(define-public (complete-bridge (bridge-id uint))
  (let ((validated-bridge-id (try! (ensure-bridge-exists bridge-id))))
    (let ((bridge (unwrap! (map-get? payment-bridges { bridge-id: validated-bridge-id }) ERR_BRIDGE_NOT_EXISTS)))
      (complete-bridge-internal validated-bridge-id bridge)
    )
  )
)

;; Emergency function - only for bridge owner
(define-public (emergency-drain (bridge-id uint))
  (let ((validated-bridge-id (try! (ensure-bridge-exists bridge-id))))
    (let ((bridge (unwrap! (map-get? payment-bridges { bridge-id: validated-bridge-id }) ERR_BRIDGE_NOT_EXISTS)))
      (asserts! (is-eq tx-sender BRIDGE_OWNER) ERR_NOT_AUTHORIZED)
      (emergency-drain-internal validated-bridge-id bridge)
    )
  )
)

;; Read-only functions
(define-read-only (get-bridge-info (bridge-id uint))
  (map-get? payment-bridges { bridge-id: bridge-id })
)

(define-read-only (get-bridge-confirmations (bridge-id uint) (sequence-num uint))
  (map-get? bridge-confirmations { bridge-id: bridge-id, sequence-num: sequence-num })
)

(define-read-only (get-member-bridges (member principal))
  (map-get? member-bridges { member: member })
)

(define-read-only (get-member-pubkey (member principal))
  (map-get? member-pubkeys { member: member })
)

(define-read-only (get-bridge-fee-rate)
  (var-get bridge-fee-rate)
)

(define-read-only (get-next-bridge-id)
  (var-get next-bridge-id)
)
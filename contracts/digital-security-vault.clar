;; Digital Security Vault 

;;=====================================================================
;; SYSTEM WIDE CONSTANTS AND CONFIGURATIONS
;; =====================================================================
;; Establishing primary constants for authorization, error handling and parameter validation

;; Administrator designation for system management
(define-constant vault-administrator tx-sender)

;; System-wide error codes for robust error handling
(define-constant error-access-denied (err u100))             ;; Access violation error
(define-constant error-insufficient-assets (err u101))       ;; Not enough resources error
(define-constant error-transaction-rejected (err u102))      ;; Failed asset movement error
(define-constant error-parameter-invalid (err u103))         ;; Bad parameter supplied error
(define-constant error-protection-cost-invalid (err u104))   ;; Invalid protection pricing error
(define-constant error-capacity-exceeded (err u105))         ;; Resource limitation error
(define-constant error-protection-unavailable (err u106))    ;; Protection plan not found error
(define-constant error-rate-invalid (err u107))              ;; Invalid calculation rate error
(define-constant error-recovery-failed (err u108))           ;; Failed recovery attempt error

;; =====================================================================
;; CONFIGURABLE SYSTEM PARAMETERS
;; =====================================================================
;; Configuration variables that affect system behavior and limits

;; Base protection rate percentage (multiplied by 100, so 500 = 5%)
(define-data-var protection-rate uint u500)

;; Maximum total capacity of the collective security pool
(define-data-var total-capacity-limit uint u1000000)

;; Current collective security pool balance
(define-data-var pool-resource-total uint u0)

;; Maximum deposit allowed per participant
(define-data-var max-participant-contribution uint u10000)

;; =====================================================================
;; DATA STORAGE STRUCTURES
;; =====================================================================
;; Maps used to track participant assets and protection plan details

;; Tracks participant's deposited assets (in STX)
(define-map participant-deposit-ledger principal uint)

;; Tracks participant's protected assets (in STX) 
(define-map participant-protected-assets principal uint)

;; Stores detailed information about participant protection plans
(define-map protection-plan-registry 
  {participant: principal} 
  {coverage: uint, fee-rate: uint, status: bool})

;; =====================================================================
;; INTERNAL UTILITY FUNCTIONS
;; =====================================================================

;; Determine recovery amount based on coverage amount and protection rate
(define-private (determine-recovery-amount (coverage-amount uint))
  (/ (* coverage-amount (var-get protection-rate)) u100))

;; Update collective security pool with specified adjustment
(define-private (adjust-pool-resources (adjustment int))
  (let (
    (current-total (var-get pool-resource-total))
    (adjusted-total (if (< adjustment 0)
                     (if (>= current-total (to-uint (- 0 adjustment)))
                         (- current-total (to-uint (- 0 adjustment)))
                         u0)
                     (+ current-total (to-uint adjustment))))
  )
    (asserts! (<= adjusted-total (var-get total-capacity-limit)) error-capacity-exceeded)
    (var-set pool-resource-total adjusted-total)
    (ok true)))

;; =====================================================================
;; PARTICIPANT-FACING OPERATIONS
;; =====================================================================

;; Deposit assets to the collective security pool
(define-public (deposit-assets (amount uint))
  (let (
    (current-assets (default-to u0 (map-get? participant-deposit-ledger tx-sender)))
    (new-assets-total (+ current-assets amount))
  )
    (asserts! (<= new-assets-total (var-get max-participant-contribution)) error-capacity-exceeded)
    (map-set participant-deposit-ledger tx-sender new-assets-total)
    (try! (adjust-pool-resources (to-int amount)))
    (ok true)))

;; Acquire a protection plan with specified parameters
(define-public (acquire-protection-plan (coverage-amount uint) (fee-rate uint))
  (let (
    (available-assets (default-to u0 (map-get? participant-deposit-ledger tx-sender)))
    (new-protected-total (+ (default-to u0 (map-get? participant-protected-assets tx-sender)) coverage-amount))
  )
    (asserts! (> coverage-amount u0) error-parameter-invalid)
    (asserts! (>= available-assets coverage-amount) error-insufficient-assets)
    (asserts! (<= fee-rate (var-get protection-rate)) error-rate-invalid)

    ;; Move assets from deposit to protected status
    (map-set participant-deposit-ledger tx-sender (- available-assets coverage-amount))
    (map-set participant-protected-assets tx-sender new-protected-total)

    ;; Record protection plan details
    (map-set protection-plan-registry {participant: tx-sender} 
             {coverage: coverage-amount, fee-rate: fee-rate, status: true})

    (ok true)))

;; Process a recovery request for a participant
(define-public (process-recovery-request (beneficiary principal) (coverage-amount uint))
  (let (
    (protection-details (default-to {coverage: u0, fee-rate: u0, status: false} 
                                   (map-get? protection-plan-registry {participant: beneficiary})))
    (calculated-recovery (determine-recovery-amount coverage-amount))
    (available-pool-resources (var-get pool-resource-total))
  )
    (asserts! (get status protection-details) error-protection-unavailable)
    (asserts! (>= available-pool-resources calculated-recovery) error-recovery-failed)

    ;; Update protected assets balance
    (let (
      (protected-balance (default-to u0 (map-get? participant-protected-assets beneficiary)))
      (remaining-protected (- protected-balance calculated-recovery))
    )
      (asserts! (>= protected-balance calculated-recovery) error-recovery-failed)
      (map-set participant-protected-assets beneficiary remaining-protected)
    )
    (var-set pool-resource-total (- available-pool-resources calculated-recovery))
    (ok true)))

;; Suspend an active protection plan
(define-public (suspend-protection-plan)
  (begin
    (let ((plan-details (default-to {coverage: u0, fee-rate: u0, status: false} 
                                    (map-get? protection-plan-registry {participant: tx-sender}))))
      ;; Verify plan is active
      (asserts! (get status plan-details) error-protection-unavailable)
      ;; Update plan status to inactive
      (map-set protection-plan-registry {participant: tx-sender} 
               {coverage: (get coverage plan-details), 
                fee-rate: (get fee-rate plan-details), 
                status: false})
      (ok true))))

;; Terminate and refund an active protection plan
(define-public (terminate-protection-plan)
  (begin
    (let ((plan-details (default-to {coverage: u0, fee-rate: u0, status: false} 
                                    (map-get? protection-plan-registry {participant: tx-sender}))))
      ;; Verify plan is active
      (asserts! (get status plan-details) error-protection-unavailable)
      ;; Return protected assets to regular deposit
      (map-set participant-deposit-ledger tx-sender 
               (+ (default-to u0 (map-get? participant-deposit-ledger tx-sender)) (get coverage plan-details)))
      ;; Deactivate the protection plan
      (map-set protection-plan-registry {participant: tx-sender} 
               {coverage: (get coverage plan-details), fee-rate: (get fee-rate plan-details), status: false})
      (ok true))))

;; Request partial recovery from active plan
(define-public (request-partial-recovery (amount uint))
  (begin
    (let ((plan-details (default-to {coverage: u0, fee-rate: u0, status: false} 
                                    (map-get? protection-plan-registry {participant: tx-sender}))))
      ;; Verify plan status and capacity
      (asserts! (get status plan-details) error-protection-unavailable)
      (asserts! (>= (get coverage plan-details) amount) error-recovery-failed)
      ;; Process recovery adjustment
      (try! (adjust-pool-resources (- (to-int (determine-recovery-amount amount)))))
      (map-set protection-plan-registry {participant: tx-sender} 
               {coverage: (- (get coverage plan-details) amount), 
                fee-rate: (get fee-rate plan-details), 
                status: true})
      (ok true))))

;; Enhance existing protection plan coverage
(define-public (enhance-protection-coverage (additional-amount uint))
  (begin
    (let ((plan-details (default-to {coverage: u0, fee-rate: u0, status: false} 
                                    (map-get? protection-plan-registry {participant: tx-sender}))))
      ;; Verify plan is active
      (asserts! (get status plan-details) error-protection-unavailable)
      ;; Verify sufficient deposit available
      (asserts! (>= (default-to u0 (map-get? participant-deposit-ledger tx-sender)) additional-amount) 
                error-insufficient-assets)
      ;; Adjust balances
      (map-set participant-deposit-ledger tx-sender 
               (- (default-to u0 (map-get? participant-deposit-ledger tx-sender)) additional-amount))
      (map-set protection-plan-registry {participant: tx-sender} 
               {coverage: (+ (get coverage plan-details) additional-amount), 
                fee-rate: (get fee-rate plan-details), 
                status: true})
      (ok true))))

;; =====================================================================
;; ADMINISTRATIVE OPERATIONS
;; =====================================================================

;; Process multiple recovery requests in batch
;; Allows administrator to efficiently handle multiple claims
(define-public (bulk-process-recovery-requests (requests (list 10 {beneficiary: principal, amount: uint})))
  (begin
    ;; Administrative access check
    (asserts! (is-eq tx-sender vault-administrator) error-access-denied)
    ;; Process each request in sequence
    (fold process-individual-request requests (ok true))))

;; Helper function to process individual recovery requests
(define-private (process-individual-request 
                 (request {beneficiary: principal, amount: uint}) 
                 (previous-result (response bool uint)))
  (begin
    ;; Check if previous operations succeeded
    (asserts! (is-ok previous-result) previous-result)
    ;; Process current request
    (let ((beneficiary-plan (default-to {coverage: u0, fee-rate: u0, status: false} 
                                      (map-get? protection-plan-registry {participant: (get beneficiary request)}))))
      ;; Verify plan status
      (if (get status beneficiary-plan)
          (begin
            ;; Calculate recovery amount
            (let ((recovery-amount (determine-recovery-amount (get amount request))))
              ;; Verify pool has sufficient resources
              (if (>= (var-get pool-resource-total) recovery-amount)
                  (begin
                    ;; Update pool resources
                    (var-set pool-resource-total (- (var-get pool-resource-total) recovery-amount))
                    ;; Record transaction details
                    (print {event: "bulk-recovery", 
                            beneficiary: (get beneficiary request), 
                            requested: (get amount request), 
                            provided: recovery-amount})
                    ;; Adjust plan coverage
                    (map-set protection-plan-registry {participant: (get beneficiary request)} 
                             {coverage: (- (get coverage beneficiary-plan) (get amount request)), 
                              fee-rate: (get fee-rate beneficiary-plan), 
                              status: (> (- (get coverage beneficiary-plan) (get amount request)) u0)})
                    (ok true))
                  error-recovery-failed)))
          error-protection-unavailable))))

;; Modify the protection rate percentage
;; Administrative function to adjust system parameters
;; @param new-rate: The updated rate percentage (x100)
(define-public (adjust-protection-rate (new-rate uint))
  (begin
    ;; Administrative access verification
    (asserts! (is-eq tx-sender vault-administrator) error-access-denied)
    ;; Rate parameter validation (between 1% and 20%)
    (asserts! (and (>= new-rate u100) (<= new-rate u2000)) error-rate-invalid)
    ;; Update system parameter
    (var-set protection-rate new-rate)
    ;; Report success
    (ok true)))

;; Modify the capacity limits for pools and participants
;; Administrative function to adjust system capacity
;; @param new-total-limit: Updated capacity for entire collective pool
;; @param new-participant-limit: Updated maximum per participant
(define-public (adjust-capacity-limits (new-total-limit uint) (new-participant-limit uint))
  (begin
    ;; Administrative access verification
    (asserts! (is-eq tx-sender vault-administrator) error-access-denied)
    ;; Parameter validation
    (asserts! (and (>= new-total-limit u1000000) (<= new-total-limit u1000000000)) error-parameter-invalid)
    (asserts! (and (>= new-participant-limit u1000) (<= new-participant-limit u100000)) error-parameter-invalid)
    ;; Update system parameters
    (var-set total-capacity-limit new-total-limit)
    (var-set max-participant-contribution new-participant-limit)
    ;; Report success
    (ok true)))

;; Extract surplus assets from collective pool when exceeding reserve requirements
;; Administrative function for system maintenance
;; @param amount: Surplus amount to extract
;; @param destination: Recipient of extracted assets
(define-public (extract-surplus-assets (amount uint) (destination principal))
  (let (
    (current-resources (var-get pool-resource-total))
    (minimum-required-reserve (/ (* current-resources u80) u100)) ;; 80% reserve requirement
  )
    ;; Administrative access verification
    (asserts! (is-eq tx-sender vault-administrator) error-access-denied)
    ;; Verify extraction maintains reserve requirements
    (asserts! (>= (- current-resources amount) minimum-required-reserve) error-insufficient-assets)
    ;; Report success
    (ok true)))

;; =====================================================================
;; PARTICIPANT UTILITY FUNCTIONS
;; =====================================================================

;; Extend protection plan duration
;; Allows participants to prolong their coverage period
;; @param extension-days: Number of days to extend coverage
(define-public (extend-coverage-duration (extension-days uint))
  (let ((plan-details (default-to {coverage: u0, fee-rate: u0, status: false} 
                                  (map-get? protection-plan-registry {participant: tx-sender})))
        (duration-fee (/ (* (get coverage plan-details) extension-days) u365)))
    ;; Verify plan is active
    (asserts! (get status plan-details) error-protection-unavailable)
    ;; Verify sufficient balance for extension fee
    (asserts! (>= (default-to u0 (map-get? participant-deposit-ledger tx-sender)) duration-fee) 
              error-insufficient-assets)
    ;; Process fee payment
    (map-set participant-deposit-ledger tx-sender 
             (- (default-to u0 (map-get? participant-deposit-ledger tx-sender)) duration-fee))
    ;; Add fee to collective pool
    (try! (adjust-pool-resources (to-int duration-fee)))
    ;; Record transaction
    (print {event: "duration-extended", participant: tx-sender, days-extended: extension-days, fee: duration-fee})
    (ok true)))

;; Transfer plan ownership to another entity
;; Allows participants to reassign their protection plan
;; @param new-holder: Principal address of new plan holder
(define-public (transfer-plan-ownership (new-holder principal))
  (let ((plan-details (default-to {coverage: u0, fee-rate: u0, status: false} 
                                  (map-get? protection-plan-registry {participant: tx-sender}))))
    ;; Verify plan is active
    (asserts! (get status plan-details) error-protection-unavailable)
    ;; Verify new holder doesn't have an active plan
    (let ((new-holder-plan (default-to {coverage: u0, fee-rate: u0, status: false} 
                                      (map-get? protection-plan-registry {participant: new-holder}))))
      (asserts! (not (get status new-holder-plan)) error-protection-unavailable)
      ;; Remove plan from current holder
      (map-delete protection-plan-registry {participant: tx-sender})
      ;; Record transaction
      (print {event: "plan-transferred", from: tx-sender, to: new-holder, coverage: (get coverage plan-details)})
      (ok true))))

;; Add critical incident protection to existing plan
;; Provides enhanced protection for high-risk situations
;; @param supplemental-coverage: Additional coverage amount for critical incidents
;; @param crisis-rate: Premium rate for critical incident protection
(define-public (add-critical-incident-protection (supplemental-coverage uint) (crisis-rate uint))
  (let ((plan-details (default-to {coverage: u0, fee-rate: u0, status: false} 
                                  (map-get? protection-plan-registry {participant: tx-sender})))
        (available-assets (default-to u0 (map-get? participant-deposit-ledger tx-sender))))
    ;; Verify plan is active
    (asserts! (get status plan-details) error-protection-unavailable)
    ;; Validate crisis rate (must exceed standard rate)
    (asserts! (> crisis-rate (var-get protection-rate)) error-rate-invalid)
    ;; Verify sufficient balance
    (asserts! (>= available-assets supplemental-coverage) error-insufficient-assets)
    ;; Process asset transfer
    (map-set participant-deposit-ledger tx-sender (- available-assets supplemental-coverage))
    ;; Update protection plan
    (map-set protection-plan-registry {participant: tx-sender} 
             {coverage: (+ (get coverage plan-details) supplemental-coverage), 
              fee-rate: crisis-rate, 
              status: true})
    ;; Update collective pool
    (try! (adjust-pool-resources (to-int supplemental-coverage)))
    ;; Record transaction
    (print {event: "critical-protection-added", 
            participant: tx-sender, 
            amount: supplemental-coverage, 
            rate: crisis-rate})
    (ok true)))



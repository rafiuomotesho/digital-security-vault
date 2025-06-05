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

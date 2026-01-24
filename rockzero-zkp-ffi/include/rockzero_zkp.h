#ifndef ROCKZERO_ZKP_H
#define ROCKZERO_ZKP_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * FFI result structure for returning data to Flutter
 */
typedef struct FfiResult {
  /**
   * Success flag: 1 = success, 0 = error
   */
  int success;
  /**
   * Result data (JSON string, base64 encoded proof, etc.)
   * Caller must free this with rz_zkp_free_string
   */
  char *data;
  /**
   * Error message if success == 0
   * Caller must free this with rz_zkp_free_string
   */
  char *error;
} FfiResult;

/**
 * Register a password and generate PasswordRegistration
 *
 * # Safety
 * - `password` must be a valid null-terminated UTF-8 string
 * - The returned FfiResult must be freed using rz_zkp_free_result
 */
struct FfiResult rz_zkp_register_password(const char *password);

/**
 * Generate enhanced password proof with full Bulletproofs range proof
 *
 * # Safety
 * - All string parameters must be valid null-terminated UTF-8 strings
 * - The returned FfiResult must be freed using rz_zkp_free_result
 */
struct FfiResult rz_zkp_generate_enhanced_proof(const char *password,
                                                const char *registration_json,
                                                const char *context);

/**
 * Verify enhanced password proof
 *
 * # Safety
 * - All string parameters must be valid null-terminated UTF-8 strings
 * - The returned FfiResult must be freed using rz_zkp_free_result
 */
struct FfiResult rz_zkp_verify_enhanced_proof(const char *proof_base64,
                                              const char *registration_json,
                                              const char *expected_context,
                                              long long max_age_seconds);

/**
 * Calculate password entropy in bits
 *
 * # Safety
 * - `password` must be a valid null-terminated UTF-8 string
 */
long long rz_zkp_calculate_entropy(const char *password);

/**
 * Get minimum required password entropy
 */
long long rz_zkp_min_entropy_bits(void);

/**
 * Free a string returned by FFI functions
 *
 * # Safety
 * - `ptr` must have been returned by an FFI function in this library
 * - Must only be called once per pointer
 */
void rz_zkp_free_string(char *ptr);

/**
 * Free an FfiResult structure
 *
 * # Safety
 * - `result` must have been returned by an FFI function in this library
 * - Must only be called once per result
 */
void rz_zkp_free_result(struct FfiResult result);

/**
 * Clear used nonces (for testing purposes)
 */
void rz_zkp_clear_nonces(void);

/**
 * Get library version
 */
const char *rz_zkp_version(void);

#endif /* ROCKZERO_ZKP_H */

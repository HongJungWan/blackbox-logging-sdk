package io.github.hongjungwan.blackbox.api.annotation;

/**
 * Defines the types of PII (Personally Identifiable Information) masking strategies.
 *
 * <p>Each type corresponds to a specific masking pattern optimized for that data type.</p>
 *
 * <h2>Masking Examples:</h2>
 * <ul>
 *   <li>{@link #RRN}: 123456-1234567 -> 123456-*******</li>
 *   <li>{@link #PHONE}: 010-1234-5678 -> 010-****-5678</li>
 *   <li>{@link #EMAIL}: user@example.com -> u***@example.com</li>
 *   <li>{@link #CREDIT_CARD}: 1234-5678-9012-3456 -> ****-****-****-3456</li>
 *   <li>{@link #PASSWORD}: anyPassword -> ********</li>
 *   <li>{@link #SSN}: 123-45-6789 -> ***-**-6789</li>
 *   <li>{@link #NAME}: John Doe -> J*** D**</li>
 *   <li>{@link #ADDRESS}: 123 Main St, City -> *** **** **, ****</li>
 *   <li>{@link #ACCOUNT_NUMBER}: 1234567890 -> ******7890</li>
 * </ul>
 *
 * @since 8.0.0
 * @see Mask
 */
public enum MaskType {

    /**
     * Korean Resident Registration Number (RRN).
     * Format: YYMMDD-GNNNNNN
     * Masking: Preserves birth date, masks gender and serial digits.
     * Example: 123456-1234567 -> 123456-*******
     */
    RRN,

    /**
     * Phone number.
     * Masking: Preserves area code and last 4 digits, masks middle section.
     * Example: 010-1234-5678 -> 010-****-5678
     */
    PHONE,

    /**
     * Email address.
     * Masking: Preserves first character and domain, masks local part.
     * Example: user@example.com -> u***@example.com
     */
    EMAIL,

    /**
     * Credit card number.
     * Masking: Preserves last 4 digits for identification, masks the rest.
     * Example: 1234-5678-9012-3456 -> ****-****-****-3456
     */
    CREDIT_CARD,

    /**
     * Password.
     * Masking: Complete masking with fixed-length asterisks.
     * Example: anyPassword -> ********
     */
    PASSWORD,

    /**
     * US Social Security Number (SSN).
     * Masking: Preserves last 4 digits, masks area and group numbers.
     * Example: 123-45-6789 -> ***-**-6789
     */
    SSN,

    /**
     * Person name.
     * Masking: Preserves first character of each word, masks the rest.
     * Example: John Doe -> J*** D**
     */
    NAME,

    /**
     * Physical address.
     * Masking: Complete masking while preserving structure.
     * Example: 123 Main St -> *** **** **
     */
    ADDRESS,

    /**
     * Bank account number.
     * Masking: Preserves last 4 digits, masks the rest.
     * Example: 1234567890 -> ******7890
     */
    ACCOUNT_NUMBER
}

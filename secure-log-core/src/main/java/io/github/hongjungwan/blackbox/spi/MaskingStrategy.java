package io.github.hongjungwan.blackbox.spi;

/**
 * SPI for PII masking strategies.
 *
 * <p>Implement this interface to provide custom masking logic for
 * specific types of sensitive data.</p>
 *
 * <h2>Built-in Strategies:</h2>
 * <ul>
 *   <li>RRN (Resident Registration Number): 123456-******* </li>
 *   <li>Credit Card: ****-****-****-3456</li>
 *   <li>Password: ********</li>
 *   <li>SSN: ***-**-6789</li>
 * </ul>
 *
 * <h2>Custom Strategy Example:</h2>
 * <pre>{@code
 * public class PhoneNumberMaskingStrategy implements MaskingStrategy {
 *     @Override
 *     public String getPatternName() {
 *         return "phone";
 *     }
 *
 *     @Override
 *     public char[] mask(char[] input, int offset, int length) {
 *         char[] result = new char[length];
 *         // Mask middle digits: 010-****-1234
 *         for (int i = 0; i < length; i++) {
 *             if (i >= 4 && i <= 7) {
 *                 result[i] = '*';
 *             } else {
 *                 result[i] = input[offset + i];
 *             }
 *         }
 *         return result;
 *     }
 *
 *     @Override
 *     public boolean matches(String fieldName) {
 *         return fieldName.contains("phone") || fieldName.contains("tel");
 *     }
 * }
 * }</pre>
 *
 * @since 8.0.0
 */
public interface MaskingStrategy {

    /**
     * Get the pattern name for this strategy.
     *
     * @return the unique name identifying this masking pattern (e.g., "rrn", "credit_card")
     */
    String getPatternName();

    /**
     * Mask the input character array.
     *
     * <p>IMPORTANT: For zero-allocation, implementations should
     * manipulate char arrays directly without creating String objects.</p>
     *
     * @param input The input character array
     * @param offset Start offset in the array
     * @param length Number of characters to process
     * @return Masked character array
     */
    char[] mask(char[] input, int offset, int length);

    /**
     * Check if this strategy should apply to the given field name.
     *
     * @param fieldName The field name to check
     * @return true if this strategy handles this field
     */
    boolean matches(String fieldName);

    /**
     * Priority for strategy selection (lower = higher priority).
     * Default is 500 (NORMAL).
     *
     * @return the priority value where lower numbers indicate higher priority
     */
    default int priority() {
        return 500;
    }
}

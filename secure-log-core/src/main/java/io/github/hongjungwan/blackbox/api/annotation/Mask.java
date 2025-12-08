package io.github.hongjungwan.blackbox.api.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a field or getter method for automatic PII masking.
 *
 * <p>When an object containing fields annotated with {@code @Mask} is processed
 * by the {@link io.github.hongjungwan.blackbox.core.security.AnnotationMaskingProcessor},
 * the values are automatically masked according to the specified {@link MaskType}.</p>
 *
 * <h2>Usage Examples:</h2>
 * <pre>{@code
 * public class EmployeeDto {
 *     @Mask(MaskType.RRN)
 *     private String residentNumber;
 *
 *     @Mask(MaskType.PHONE)
 *     private String phoneNumber;
 *
 *     @Mask(MaskType.EMAIL)
 *     private String email;
 *
 *     @Mask(MaskType.CREDIT_CARD)
 *     private String cardNumber;
 *
 *     @Mask(MaskType.PASSWORD)
 *     private String password;
 * }
 *
 * // Usage with PiiMasker
 * PiiMasker masker = new PiiMasker(config);
 * EmployeeDto masked = masker.maskObject(originalDto);
 * }</pre>
 *
 * <h2>Supported Target Elements:</h2>
 * <ul>
 *   <li>{@link ElementType#FIELD} - Instance fields</li>
 *   <li>{@link ElementType#METHOD} - Getter methods (for record types or custom accessors)</li>
 * </ul>
 *
 * <h2>Thread Safety:</h2>
 * <p>The annotation processing is thread-safe. Multiple threads can process
 * different instances of the same class concurrently.</p>
 *
 * @since 8.0.0
 * @see MaskType
 * @see io.github.hongjungwan.blackbox.core.security.AnnotationMaskingProcessor
 */
@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Mask {

    /**
     * The type of masking to apply to the annotated field or method.
     *
     * @return the masking type
     */
    MaskType value();
}
